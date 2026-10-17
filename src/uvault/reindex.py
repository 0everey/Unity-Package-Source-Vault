"""Rebuild outdated metadata from immutable bytes without republishing payloads."""
import hashlib
from . import sources, inventory

def reindex_queue(queue, progress=None):
    changed=0
    current=getattr(inventory,"FINGERPRINT_PRODUCER",None)
    if current is None:
        raise ValueError("Inventory must declare its fingerprint producer version")
    for package in queue["packages"]:
        for version in package.get("versions",[]):
            previous=version.get("fingerprint") or {}
            artifact=version.get("artifact") or {}
            actual_producer=previous.get("fingerprintProducer") or {}
            producer_matches=all(actual_producer.get(key)==value for key,value in current.items())
            binaries=previous.get("binaryFingerprints") or [file for file in previous.get("files",[]) if file.get("path","").lower().endswith(".dll")]
            if binaries:
                from .managed import producer_identity
                managed=producer_identity()
                if managed.get("available"):
                    producer_matches=producer_matches and actual_producer.get("managedMetadata")==managed
            if (not previous and not version.get("reindexError")) or producer_matches or not artifact.get("sha256") or not artifact.get("url"):
                continue
            data=None
            try:
                data=sources.request_bytes(artifact["url"])
                if hashlib.sha256(data).hexdigest()!=artifact["sha256"] or len(data)!=artifact["size"]:
                    raise ValueError("Immutable artifact mismatch during reindex")
                version["fingerprint"]=inventory.fingerprint_archive(data,artifact["format"])
                version["reindexedAt"]=sources.utc_now()
                version.pop("reindexError",None)
                changed+=1
            except (ValueError,sources.SourceError) as exc:
                # Invalidate the affected ownership assertion; do not leave an
                # obsolete fingerprint available for automatic classification.
                version["previousFingerprintProducer"]=previous.get("fingerprintProducer","unversioned")
                version["fingerprint"]=None
                version["reindexError"]={"kind":type(exc).__name__,"message":str(exc)}
            finally:
                data=None
            if progress:
                progress(queue,package)
    return changed
