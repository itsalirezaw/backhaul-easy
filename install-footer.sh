stage=$(mktemp -d /tmp/backhaul-easy-install.XXXXXXXX)
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT
printf '%s' "$BUNDLE" > "$stage/bundle.b64"
unset BUNDLE
python3 - "$stage" <<'PY'
import base64, io, pathlib, stat, sys, zipfile
stage = pathlib.Path(sys.argv[1])
allowed = {'bootstrap.py', 'backhaul_easy.py', 'panel_support.py', 'install-header.sh', 'install-footer.sh'}
data = base64.b64decode((stage/'bundle.b64').read_bytes(), validate=True)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    if set(z.namelist()) != allowed or len(z.infolist()) != len(allowed):
        raise SystemExit('Unexpected installer bundle members')
    for info in z.infolist():
        if info.file_size > 2*1024*1024 or stat.S_ISLNK(info.external_attr >> 16):
            raise SystemExit('Unsafe installer member')
        (stage/info.filename).write_bytes(z.read(info))
PY
python3 "$stage/bootstrap.py" --source "$stage" --bundle "$stage/bundle.b64" "$@"
