"""
Descarga masiva SAT para CFDI recibidos o emitidos.

El módulo trabaja con credenciales ya cargadas en memoria:
- RFC del receptor / solicitante
- bytes del archivo .cer
- bytes del archivo .key
- contraseña de la llave privada

El backend real se resuelve de forma perezosa:
- `cfdiclient` si está disponible
- `zeep` + `cryptography` como fallback

La aplicación principal solo llama `execute_full_flow()` y luego importa
los XMLs devueltos.
"""

from __future__ import annotations

import base64
import io
import logging
import os
import re
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

SAT_AUTH_URL = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"
SAT_QUERY_URL = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
SAT_VERIFY_URL = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
SAT_DOWNLOAD_URL = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"

POLL_INITIAL_WAIT = 2
POLL_MAX_WAIT = 15
POLL_MAX_ATTEMPTS = int(os.getenv("SAT_POLL_MAX_ATTEMPTS", "45"))
POLL_BACKOFF_FACTOR = 1.5


def _env_int(name: str, default: int, min_value: int = 1, max_value: int = 300) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(min_value, min(max_value, value))


SAT_REQUEST_TIMEOUT = _env_int("SAT_REQUEST_TIMEOUT", 45, min_value=5, max_value=180)
SAT_VERIFY_TIMEOUT = _env_int("SAT_VERIFY_TIMEOUT", 120, min_value=30, max_value=240)
SAT_NETWORK_ATTEMPTS = _env_int("SAT_NETWORK_ATTEMPTS", 3, min_value=1, max_value=8)
SAT_NETWORK_RETRY_WAIT = _env_int("SAT_NETWORK_RETRY_WAIT", 3, min_value=1, max_value=30)
SAT_CHUNK_DAYS = _env_int("SAT_CHUNK_DAYS", 31, min_value=1, max_value=31)
DEFAULT_SAT_HOST_IPS = {
    "cfdidescargamasivasolicitud.clouda.sat.gob.mx": "13.65.17.50",
    "cfdidescargamasiva.clouda.sat.gob.mx": "40.74.244.66",
}
_ORIGINAL_GETADDRINFO = None


class SatConfigError(RuntimeError):
    pass


class SatAuthError(RuntimeError):
    pass


class SatRequestError(RuntimeError):
    pass


class SatVerifyError(RuntimeError):
    pass


class SatDownloadError(RuntimeError):
    pass


def _short_error(exc: Exception, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(exc)).strip()
    return text[:limit]


def _is_sat_connectivity_error(exc: Exception) -> bool:
    try:
        import requests

        if isinstance(
            exc,
            (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
            ),
        ):
            return True
    except Exception:
        pass

    err = str(exc).lower()
    return any(
        token in err
        for token in (
            "connecttimeout",
            "readtimeout",
            "connectionerror",
            "max retries exceeded",
            "newconnectionerror",
            "nameresolutionerror",
            "failed to resolve",
            "temporary failure in name resolution",
            "nodename nor servname",
            "timed out",
            "connection timed out",
            "network is unreachable",
            "connection refused",
        )
    )


def _sat_connectivity_message(stage: str, exc: Exception) -> str:
    return (
        f"No fue posible conectar con el servicio SAT durante {stage}. "
        "La FIEL no fue rechazada; falló la conexión, DNS o timeout contra clouda.sat.gob.mx. "
        "Verifica internet, VPN/firewall y vuelve a intentar. "
        f"Detalle técnico: {_short_error(exc)}"
    )


def _sat_host_ip_overrides() -> dict[str, str]:
    overrides = dict(DEFAULT_SAT_HOST_IPS)
    raw = os.getenv("SAT_HOST_OVERRIDES", "")
    for item in raw.split(","):
        if "=" not in item:
            continue
        host, ip = item.split("=", 1)
        host = host.strip().lower()
        ip = ip.strip()
        if host and ip:
            overrides[host] = ip
    return overrides


def _install_sat_dns_fallback():
    global _ORIGINAL_GETADDRINFO
    if _ORIGINAL_GETADDRINFO is not None:
        return

    import socket

    overrides = _sat_host_ip_overrides()
    original_getaddrinfo = socket.getaddrinfo

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        try:
            return original_getaddrinfo(host, port, family, type, proto, flags)
        except socket.gaierror:
            fallback_ip = overrides.get(str(host or "").lower())
            if not fallback_ip:
                raise
            fallback_family = socket.AF_INET6 if ":" in fallback_ip else socket.AF_INET
            logger.warning("DNS SAT no resolvió %s; usando fallback %s", host, fallback_ip)
            return original_getaddrinfo(fallback_ip, port, fallback_family, type, proto, flags)

    _ORIGINAL_GETADDRINFO = original_getaddrinfo
    socket.getaddrinfo = getaddrinfo


def _date_chunks(date_from: str, date_to: str, chunk_days: int = SAT_CHUNK_DAYS) -> list[tuple[str, str]]:
    start = datetime.strptime(date_from, "%Y-%m-%d").date()
    end = datetime.strptime(date_to, "%Y-%m-%d").date()
    chunks = []
    cursor = start
    while cursor <= end:
        chunk_end = min(cursor + timedelta(days=chunk_days - 1), end)
        chunks.append((cursor.isoformat(), chunk_end.isoformat()))
        cursor = chunk_end + timedelta(days=1)
    return chunks


def _load_certificate_bundle(cer_bytes: bytes):
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    try:
        return x509.load_der_x509_certificate(cer_bytes, default_backend())
    except Exception:
        return x509.load_pem_x509_certificate(cer_bytes, default_backend())


def _load_private_key_bundle(key_bytes: bytes, password: str):
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    password_bytes = password.encode("utf-8") if password else None
    errors = []
    for loader in (serialization.load_der_private_key, serialization.load_pem_private_key):
        try:
            return loader(key_bytes, password=password_bytes, backend=default_backend())
        except Exception as exc:
            errors.append(exc)
    joined = " | ".join(str(exc).lower() for exc in errors)
    if any(
        token in joined
        for token in (
            "password",
            "decrypt",
            "bad decrypt",
            "mac verify",
            "padding",
            "malformedframing",
            "unable to load pem file",
        )
    ):
        raise SatAuthError("Contraseña de la llave privada incorrecta o archivo .key incompatible.")
    raise SatAuthError(f"No fue posible cargar la FIEL: {errors[-1]}")


def _export_private_key_candidates(private_key):
    from cryptography.hazmat.primitives import serialization

    candidates = []
    export_variants = (
        (serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL),
        (serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL),
        (serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8),
        (serialization.Encoding.DER, serialization.PrivateFormat.PKCS8),
    )
    for encoding, private_format in export_variants:
        try:
            candidates.append(
                private_key.private_bytes(
                    encoding=encoding,
                    format=private_format,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        except Exception:
            continue
    return candidates


def validate_sat_bundle(cer_bytes: bytes, key_bytes: bytes, password: str):
    try:
        cert = _load_certificate_bundle(cer_bytes)
    except Exception as exc:
        raise SatConfigError(f"No fue posible leer el certificado .cer: {exc}") from exc

    try:
        private_key = _load_private_key_bundle(key_bytes, password)
    except SatAuthError:
        raise
    except Exception as exc:
        err = str(exc).lower()
        if "password" in err or "decrypt" in err or "mac verify" in err or "padding" in err:
            raise SatAuthError("Contraseña de la llave privada incorrecta o llave dañada.") from exc
        raise SatAuthError(f"No fue posible cargar la FIEL: {exc}") from exc

    try:
        cert_pub = cert.public_key().public_numbers()
        key_pub = private_key.public_key().public_numbers()
        if cert_pub.n != key_pub.n or cert_pub.e != key_pub.e:
            raise SatAuthError("El archivo .cer y el archivo .key no corresponden al mismo par FIEL.")
    except AttributeError as exc:
        raise SatAuthError("La FIEL debe ser una llave RSA válida.") from exc

    key_candidates = _export_private_key_candidates(private_key)
    if not key_candidates:
        raise SatAuthError("No fue posible normalizar la llave privada para su uso con SAT.")

    return {
        "certificate": cert,
        "private_key": private_key,
        "key_candidates": key_candidates,
    }


class SatDownloader:
    def __init__(self, rfc_receptor: str, cer_bytes: bytes, key_bytes: bytes, password: str):
        _install_sat_dns_fallback()
        self._creds = {
            "rfc_receptor": (rfc_receptor or "").strip().upper(),
            "cer_bytes": cer_bytes or b"",
            "key_bytes": key_bytes or b"",
            "password": password or "",
        }
        self._token = None
        self._token_expiry = None
        self._fiel = None
        self._bundle = None
        self._backend = self._detect_backend()
        if not self._creds["rfc_receptor"]:
            raise SatConfigError("RFC receptor vacío.")
        if not self._creds["cer_bytes"]:
            raise SatConfigError("Archivo CER vacío.")
        if not self._creds["key_bytes"]:
            raise SatConfigError("Archivo KEY vacío.")
        if not self._creds["password"]:
            raise SatConfigError("Contraseña de la llave privada vacía.")
        self._bundle = validate_sat_bundle(
            self._creds["cer_bytes"],
            self._creds["key_bytes"],
            self._creds["password"],
        )

    def _detect_backend(self):
        try:
            import cfdiclient  # noqa: F401
            logger.info("Backend SAT: cfdiclient")
            return "cfdiclient"
        except Exception:
            pass
        try:
            import zeep  # noqa: F401
            from cryptography.hazmat.primitives import serialization  # noqa: F401
            logger.info("Backend SAT: zeep + cryptography")
            return "zeep"
        except Exception:
            pass
        raise SatConfigError(
            "No se encontraron dependencias SAT. Instala cfdiclient o zeep+cryptography."
        )

    def _get_cfdiclient_fiel(self):
        if self._fiel is not None:
            return self._fiel
        try:
            from cfdiclient import Fiel

            if self._creds["key_bytes"] and self._creds["password"]:
                try:
                    self._fiel = Fiel(self._creds["cer_bytes"], self._creds["key_bytes"], self._creds["password"])
                    return self._fiel
                except Exception:
                    pass

            for key_bytes in self._bundle.get("key_candidates", []):
                try:
                    self._fiel = Fiel(self._creds["cer_bytes"], key_bytes, "")
                    return self._fiel
                except Exception:
                    continue

            raise SatAuthError("No fue posible cargar la FIEL con el formato de llave proporcionado.")
        except SatAuthError:
            raise
        except Exception as exc:
            err = str(exc).lower()
            if "password" in err or "contraseña" in err or "incorrect" in err:
                raise SatAuthError("Contraseña de la llave privada incorrecta.") from exc
            raise SatAuthError(f"No fue posible cargar la FIEL: {exc}") from exc

    def _load_private_key_compat(self, key_bytes, serialization, default_backend):
        password = self._creds["password"].encode()
        try:
            return serialization.load_der_private_key(
                key_bytes,
                password=password,
                backend=default_backend(),
            )
        except Exception as first_exc:
            logger.warning("DER directo no cargó; probando con OpenSSL: %s", first_exc)

        tmp = tempfile.NamedTemporaryFile(prefix="sat_key_", suffix=".key", delete=False)
        key_path = Path(tmp.name)
        try:
            tmp.close()
            key_path.write_bytes(key_bytes)
            openssl = subprocess.run(
                [
                    "openssl",
                    "rsa",
                    "-inform",
                    "DER",
                    "-in",
                    str(key_path),
                    "-passin",
                    "fd:0",
                ],
                input=password + b"\n",
                capture_output=True,
                check=False,
            )
            if openssl.returncode != 0:
                stderr = openssl.stderr.decode("utf-8", errors="ignore").strip()
                raise SatAuthError(
                    "No fue posible descifrar la llave privada FIEL. "
                    f"OpenSSL respondió: {stderr or 'error desconocido'}"
                )

            return serialization.load_pem_private_key(
                openssl.stdout,
                password=None,
                backend=default_backend(),
            )
        finally:
            try:
                key_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _call_sat_with_retries(self, stage: str, call, error_cls, attempts: int | None = None):
        last_exc = None
        attempts_limit = attempts or SAT_NETWORK_ATTEMPTS
        for attempt in range(1, attempts_limit + 1):
            try:
                return call()
            except Exception as exc:
                if not _is_sat_connectivity_error(exc):
                    raise
                last_exc = exc
                if attempt >= attempts_limit:
                    break
                logger.warning(
                    "Timeout/conexión SAT en %s. Reintento %s/%s: %s",
                    stage,
                    attempt + 1,
                    attempts_limit,
                    _short_error(exc, 220),
                )
                time.sleep(SAT_NETWORK_RETRY_WAIT * attempt)
        raise error_cls(_sat_connectivity_message(stage, last_exc)) from last_exc

    def authenticate(self):
        if self._token and self._token_expiry:
            remaining = (self._token_expiry - datetime.now(timezone.utc)).total_seconds()
            if remaining > 30:
                return self._token

        try:
            if self._backend == "cfdiclient":
                token = self._auth_cfdiclient()
            else:
                token = self._auth_zeep()
            self._token = token
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=270)
            return token
        except SatAuthError:
            raise
        except Exception as exc:
            raise SatAuthError(f"Error inesperado en autenticación SAT: {exc}") from exc

    def _auth_cfdiclient(self):
        try:
            from cfdiclient import Autenticacion

            def call():
                auth = Autenticacion(self._get_cfdiclient_fiel(), verify=True, timeout=SAT_REQUEST_TIMEOUT)
                token = auth.obtener_token()
                if not token:
                    raise SatAuthError("El SAT devolvió un token vacío.")
                return token

            return self._call_sat_with_retries("autenticación", call, SatAuthError)
        except SatAuthError:
            raise
        except Exception as exc:
            err = str(exc).lower()
            if "password" in err or "contraseña" in err or "incorrect" in err:
                raise SatAuthError("Contraseña de la llave privada incorrecta.") from exc
            raise SatAuthError(f"Error de autenticación con cfdiclient: {exc}") from exc

    def _auth_zeep(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            import zeep
            import uuid as _uuid

            cer_bytes = self._creds["cer_bytes"]
            key_bytes = self._creds["key_bytes"]

            try:
                cert = x509.load_der_x509_certificate(cer_bytes, default_backend())
            except Exception:
                cert = x509.load_pem_x509_certificate(cer_bytes, default_backend())

            private_key = self._load_private_key_compat(key_bytes, serialization, default_backend)
            now_utc = datetime.now(timezone.utc)
            created = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            expires = (now_utc + timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
            _ = private_key.sign(
                f"{created}{expires}".encode(),
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
            _ = cert.public_bytes(serialization.Encoding.DER)

            client = zeep.Client(f"{SAT_AUTH_URL}?wsdl")
            response = client.service.Autentica()
            if not response:
                raise SatAuthError("SAT devolvió respuesta vacía en autenticación.")
            return str(response)
        except SatAuthError:
            raise
        except Exception as exc:
            raise SatAuthError(f"Error en autenticación manual zeep: {exc}") from exc

    def request_download(self, date_from: str, date_to: str, request_type: str = "received") -> str:
        token = self.authenticate()
        rfc = self._creds["rfc_receptor"]

        from_dt = datetime.strptime(date_from, "%Y-%m-%d")
        to_dt = datetime.strptime(date_to, "%Y-%m-%d")
        if from_dt > to_dt:
            raise SatRequestError("La fecha inicial debe ser anterior a la final.")
        if (to_dt - from_dt).days > 31:
            raise SatRequestError("El rango no puede superar 31 días por solicitud.")

        if self._backend == "cfdiclient":
            return self._request_cfdiclient(token, date_from, date_to, request_type, rfc)
        return self._request_zeep(token, date_from, date_to, request_type, rfc)

    def _request_cfdiclient(self, token, date_from, date_to, request_type, rfc):
        try:
            from cfdiclient import SolicitaDescargaEmitidos, SolicitaDescargaRecibidos

            from_dt = datetime.strptime(date_from, "%Y-%m-%d")
            to_date = datetime.strptime(date_to, "%Y-%m-%d").date()
            today = datetime.now().date()
            to_dt = datetime.now().replace(microsecond=0) if to_date >= today else datetime.combine(to_date, datetime.max.time()).replace(microsecond=0)

            if request_type == "received":
                def call():
                    descarga = SolicitaDescargaRecibidos(self._get_cfdiclient_fiel(), verify=True, timeout=SAT_REQUEST_TIMEOUT)
                    return descarga.solicitar_descarga(
                        token,
                        rfc,
                        from_dt,
                        to_dt,
                        rfc_receptor=rfc,
                        tipo_solicitud="CFDI",
                        estado_comprobante="Vigente",
                    )
            else:
                def call():
                    descarga = SolicitaDescargaEmitidos(self._get_cfdiclient_fiel(), verify=True, timeout=SAT_REQUEST_TIMEOUT)
                    return descarga.solicitar_descarga(
                        token,
                        rfc,
                        from_dt,
                        to_dt,
                        rfc_emisor=rfc,
                        tipo_solicitud="CFDI",
                        estado_comprobante="Vigente",
                    )

            result = self._call_sat_with_retries("solicitud de descarga", call, SatRequestError)
            request_id = None
            if result:
                request_id = result.get("request_id") or result.get("id_solicitud")
            if not request_id:
                raise SatRequestError(f"SAT no devolvió ID de solicitud. Respuesta: {result}")
            return str(request_id)
        except SatRequestError:
            raise
        except Exception as exc:
            raise SatRequestError(f"Error en solicitud con cfdiclient: {exc}") from exc

    def _request_zeep(self, token, date_from, date_to, request_type, rfc):
        import zeep

        client = zeep.Client(f"{SAT_QUERY_URL}?wsdl")
        to_date = datetime.strptime(date_to, "%Y-%m-%d").date()
        today = datetime.now().date()
        date_to_value = (
            datetime.now().replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%S")
            if to_date >= today
            else f"{date_to}T23:59:59"
        )
        params = {
            "solicitud": {
                "FechaInicial": f"{date_from}T00:00:00",
                "FechaFinal": date_to_value,
                "TipoSolicitud": "CFDI",
                "TipoComprobante": "",
                "EstadoComprobante": "Vigente",
                "RfcEmisor": rfc if request_type == "issued" else "",
                "RfcReceptores": {"RfcReceptor": [rfc]} if request_type == "received" else None,
                "RfcSolicitante": rfc,
            }
        }
        result = client.service.SolicitaDescarga(**params, _soapheaders={"Authorization": f"Bearer {token}"})
        if not result or not hasattr(result, "IdSolicitud"):
            raise SatRequestError(f"SAT no devolvió IdSolicitud. Respuesta: {result}")
        return str(result.IdSolicitud)

    def verify_request(self, request_id: str, progress_callback=None, max_attempts: int | None = None) -> dict:
        token = self.authenticate()
        rfc = self._creds["rfc_receptor"]
        wait = POLL_INITIAL_WAIT
        attempts_limit = max_attempts or POLL_MAX_ATTEMPTS

        for attempt in range(1, attempts_limit + 1):
            try:
                result = self._verify_once(token, request_id, rfc)
                status_code = result.get("status_code", "")
                status = result.get("status", "")
                package_ids = result.get("package_ids", [])
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "verify",
                            "attempt": attempt,
                            "status_code": status_code,
                            "status": status,
                            "package_ids": package_ids,
                            "packages_count": len(package_ids),
                            "cfdis_count": result.get("cfdis_count", 0),
                        }
                    )

                if status_code in ("3000", "5000", "3") or status in ("Finished", "Terminada"):
                    return {
                        "status": status or status_code,
                        "package_ids": package_ids,
                        "packages_count": len(package_ids),
                        "cfdis_count": result.get("cfdis_count", 0),
                    }

                if status_code in ("2000", "1003", "1004", "1", "2") or status in ("InProgress", "EnProceso"):
                    time.sleep(wait)
                    wait = min(wait * POLL_BACKOFF_FACTOR, POLL_MAX_WAIT)
                    token = self.authenticate()
                    continue

                if status_code == "0" or "error no controlado" in str(status).lower() or "token invalido" in str(status).lower():
                    time.sleep(wait)
                    wait = min(wait * POLL_BACKOFF_FACTOR, POLL_MAX_WAIT)
                    token = self.authenticate()
                    continue

                raise SatVerifyError(f"SAT devolvió estado inesperado: {status_code} - {status}")
            except SatVerifyError as exc:
                if not _is_sat_connectivity_error(exc):
                    raise
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "verify",
                            "attempt": attempt,
                            "status_code": "",
                            "status": "SAT no respondió a tiempo; reintentando verificación",
                            "package_ids": [],
                            "packages_count": 0,
                            "cfdis_count": 0,
                        }
                    )
                if attempt >= attempts_limit:
                    raise SatVerifyError(
                        f"Se agotaron los {attempts_limit} intentos de verificación. Último error: {exc}"
                    ) from exc
                time.sleep(wait)
                wait = min(wait * POLL_BACKOFF_FACTOR, POLL_MAX_WAIT)
                try:
                    token = self.authenticate()
                except SatAuthError:
                    pass
                continue
            except Exception as exc:
                if attempt >= attempts_limit:
                    raise SatVerifyError(
                        f"Se agotaron los {attempts_limit} intentos de verificación. Último error: {exc}"
                    ) from exc
                time.sleep(wait)
                wait = min(wait * POLL_BACKOFF_FACTOR, POLL_MAX_WAIT)

        raise SatVerifyError(
            f"El SAT no terminó de preparar la solicitud después de {attempts_limit} intentos. "
            "Vuelve a intentar más tarde o usa Refrescar estado."
        )

    def _verify_once(self, token, request_id, rfc):
        try:
            if self._backend == "cfdiclient":
                from cfdiclient import VerificaSolicitudDescarga

                def call():
                    verificacion = VerificaSolicitudDescarga(self._get_cfdiclient_fiel(), verify=True, timeout=SAT_VERIFY_TIMEOUT)
                    return verificacion.verificar_descarga(token, rfc, request_id)

                result = self._call_sat_with_retries("verificación de solicitud", call, SatVerifyError, attempts=1)
                return {
                    "status_code": str(result.get("estado_solicitud", "") or ""),
                    "status": str(result.get("mensaje", "") or result.get("codigo_estado_solicitud", "") or ""),
                    "package_ids": list(result.get("paquetes", [])),
                    "cfdis_count": int(result.get("numero_cfdis", 0) or 0),
                }

            import zeep

            client = zeep.Client(f"{SAT_VERIFY_URL}?wsdl")
            response = client.service.VerificaSolicitudDescarga(
                solicitud={"IdSolicitud": request_id, "RfcSolicitante": rfc},
                _soapheaders={"Authorization": f"Bearer {token}"},
            )
            pkg_ids = []
            if hasattr(response, "IdsPaquetes") and response.IdsPaquetes:
                pkg_ids = list(response.IdsPaquetes.IdPaquete or [])
            return {
                "status_code": str(getattr(response, "CodEstatus", "")),
                "status": str(getattr(response, "EstadoSolicitud", "")),
                "package_ids": [str(p) for p in pkg_ids],
                "cfdis_count": int(getattr(response, "NumeroCFDIs", 0) or 0),
            }
        except Exception as exc:
            raise SatVerifyError(f"Error en llamada de verificación: {exc}") from exc

    def download_package(self, package_id: str) -> bytes:
        token = self.authenticate()
        rfc = self._creds["rfc_receptor"]

        try:
            if self._backend == "cfdiclient":
                from cfdiclient import DescargaMasiva

                def call():
                    descarga = DescargaMasiva(self._get_cfdiclient_fiel(), verify=True, timeout=max(SAT_REQUEST_TIMEOUT, 60))
                    return descarga.descargar_paquete(token, rfc, package_id)

                response = self._call_sat_with_retries("descarga de paquete", call, SatDownloadError)
                encoded = response.get("paquete_b64") if response else None
                if not encoded:
                    raise SatDownloadError(f"Paquete vacío devuelto por SAT para ID: {package_id}")
                zip_bytes = base64.b64decode(encoded)
            else:
                import zeep

                client = zeep.Client(f"{SAT_DOWNLOAD_URL}?wsdl")
                response = client.service.DescargarPaquete(
                    paquete={"IdPaquete": package_id, "RfcSolicitante": rfc},
                    _soapheaders={"Authorization": f"Bearer {token}"},
                )
                encoded = getattr(response, "Paquete", None)
                if not encoded:
                    raise SatDownloadError(f"Paquete vacío devuelto por SAT para ID: {package_id}")
                zip_bytes = base64.b64decode(encoded)

            if not zip_bytes:
                raise SatDownloadError(f"ZIP descargado está vacío para paquete: {package_id}")
            return zip_bytes
        except SatDownloadError:
            raise
        except Exception as exc:
            raise SatDownloadError(f"Error al descargar paquete {package_id}: {exc}") from exc

    def extract_xmls_from_zip(self, zip_bytes: bytes) -> list[dict]:
        xmls = []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for item in zf.infolist():
                    if item.is_dir():
                        continue
                    name = item.filename
                    if name.startswith("__MACOSX/") or name.endswith(".DS_Store"):
                        continue
                    if name.lower().endswith(".xml"):
                        xmls.append({"filename": Path(name).name, "content": zf.read(item)})
        except zipfile.BadZipFile as exc:
            logger.error("El paquete SAT no es un ZIP válido: %s", exc)
        return xmls

    def execute_full_flow(
        self,
        date_from: str,
        date_to: str,
        request_type: str = "received",
        progress_callback=None,
        existing_request_id: str | None = None,
    ) -> dict:
        result = {
            "request_id": None,
            "packages_count": 0,
            "xmls": [],
            "download_errors": [],
            "error": None,
            "status": "ok",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            if not existing_request_id:
                chunks = _date_chunks(date_from, date_to)
                if len(chunks) > 1:
                    return self._execute_chunked_flow(chunks, request_type, progress_callback)

            if progress_callback:
                progress_callback({"stage": "connecting", "message": "Autenticando FIEL y enviando solicitud al SAT."})

            request_id = (existing_request_id or "").strip()
            if not request_id:
                request_id = self.request_download(date_from, date_to, request_type)
            result["request_id"] = request_id
            if progress_callback:
                progress_callback({"stage": "requested", "request_id": request_id, "message": "Solicitud aceptada por el SAT."})

            verify_result = self.verify_request(request_id, progress_callback=progress_callback)
            result["packages_count"] = verify_result["packages_count"]
            if progress_callback:
                progress_callback(
                    {
                        "stage": "verified",
                        "request_id": request_id,
                        "packages_count": verify_result["packages_count"],
                        "cfdis_count": verify_result.get("cfdis_count", 0),
                        "message": "Solicitud verificada por el SAT.",
                    }
                )

            if not verify_result["package_ids"]:
                result["status"] = "no_data"
                return result

            all_xmls = []
            download_errors = []
            for pkg_id in verify_result["package_ids"]:
                try:
                    if progress_callback:
                        progress_callback({"stage": "downloading", "package_id": pkg_id, "message": f"Descargando paquete {pkg_id}."})
                    zip_bytes = self.download_package(pkg_id)
                    xmls = self.extract_xmls_from_zip(zip_bytes)
                    all_xmls.extend(xmls)
                    if progress_callback:
                        progress_callback(
                            {
                                "stage": "package_done",
                                "package_id": pkg_id,
                                "xmls_count": len(xmls),
                                "message": f"Paquete procesado: {len(xmls)} XMLs.",
                            }
                        )
                except SatDownloadError as exc:
                    download_errors.append({"package_id": pkg_id, "error": str(exc)})

            result["xmls"] = all_xmls
            result["download_errors"] = download_errors
            result["status"] = "ok"
        except SatConfigError as exc:
            result["error"] = f"Configuración FIEL incompleta: {exc}"
            result["status"] = "error"
        except SatAuthError as exc:
            message = str(exc)
            result["error"] = message if message.startswith("No fue posible conectar") else f"Error de autenticación FIEL: {message}"
            result["status"] = "error"
        except SatRequestError as exc:
            result["error"] = f"Error al solicitar descarga: {exc}"
            result["status"] = "error"
        except SatVerifyError as exc:
            result["error"] = f"Error verificando estado: {exc}"
            result["status"] = "error"
        except Exception as exc:
            result["error"] = f"Error inesperado: {exc}"
            result["status"] = "error"
            logger.exception("Error inesperado en flujo SAT")

        return result

    def _download_verified_packages(self, request_id: str, verify_result: dict, progress_callback=None) -> tuple[list[dict], list[dict]]:
        all_xmls = []
        download_errors = []
        for pkg_id in verify_result.get("package_ids", []):
            try:
                if progress_callback:
                    progress_callback({"stage": "downloading", "package_id": pkg_id, "message": f"Descargando paquete {pkg_id}."})
                zip_bytes = self.download_package(pkg_id)
                xmls = self.extract_xmls_from_zip(zip_bytes)
                all_xmls.extend(xmls)
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "package_done",
                            "package_id": pkg_id,
                            "xmls_count": len(xmls),
                            "message": f"Paquete procesado: {len(xmls)} XMLs.",
                        }
                    )
            except SatDownloadError as exc:
                download_errors.append({"request_id": request_id, "package_id": pkg_id, "error": str(exc)})
        return all_xmls, download_errors

    def _execute_chunked_flow(self, chunks: list[tuple[str, str]], request_type: str, progress_callback=None) -> dict:
        result = {
            "request_id": None,
            "packages_count": 0,
            "xmls": [],
            "download_errors": [],
            "error": None,
            "status": "ok",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        request_items = []

        try:
            if progress_callback:
                progress_callback({"stage": "connecting", "message": f"Dividiendo consulta SAT en {len(chunks)} bloques."})

            for idx, (chunk_from, chunk_to) in enumerate(chunks, 1):
                request_id = self.request_download(chunk_from, chunk_to, request_type)
                request_items.append({"request_id": request_id, "date_from": chunk_from, "date_to": chunk_to})
                result["request_id"] = ",".join(item["request_id"] for item in request_items)
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "requested",
                            "request_id": result["request_id"],
                            "message": f"Solicitud SAT {idx}/{len(chunks)} aceptada: {chunk_from} a {chunk_to}.",
                        }
                    )

            total_cfdis = 0
            for idx, item in enumerate(request_items, 1):
                if progress_callback:
                    progress_callback(
                        {
                            "stage": "verify",
                            "attempt": idx,
                            "status_code": "",
                            "status": f"Verificando bloque {idx}/{len(request_items)}",
                            "package_ids": [],
                            "packages_count": result["packages_count"],
                            "cfdis_count": total_cfdis,
                        }
                    )
                verify_result = self.verify_request(item["request_id"], progress_callback=progress_callback)
                result["packages_count"] += verify_result.get("packages_count", 0)
                total_cfdis += verify_result.get("cfdis_count", 0)
                xmls, errors = self._download_verified_packages(item["request_id"], verify_result, progress_callback)
                result["xmls"].extend(xmls)
                result["download_errors"].extend(errors)

            if result["packages_count"] == 0 and not result["xmls"]:
                result["status"] = "no_data"
            return result
        except SatConfigError as exc:
            result["error"] = f"Configuración FIEL incompleta: {exc}"
            result["status"] = "error"
        except SatAuthError as exc:
            message = str(exc)
            result["error"] = message if message.startswith("No fue posible conectar") else f"Error de autenticación FIEL: {message}"
            result["status"] = "error"
        except SatRequestError as exc:
            result["error"] = f"Error al solicitar descarga: {exc}"
            result["status"] = "error"
        except SatVerifyError as exc:
            result["error"] = f"Error verificando estado: {exc}"
            result["status"] = "error"
        except Exception as exc:
            result["error"] = f"Error inesperado: {exc}"
            result["status"] = "error"
            logger.exception("Error inesperado en flujo SAT por bloques")
        return result
