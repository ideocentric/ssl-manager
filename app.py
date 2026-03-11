import io
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import wraps
from io import BytesIO
from zipfile import ZipFile

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_login import (
    LoginManager, UserMixin, current_user,
    login_required, login_user, logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///ssl_manager.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "ssl-manager-secret-key-change-in-prod")

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model, UserMixin):
    __tablename__ = "user"

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(64), unique=True, nullable=False)
    email         = db.Column(db.String(256), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role          = db.Column(db.String(16), default="user", nullable=False)  # superadmin | user
    active        = db.Column(db.Boolean, default=True, nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    # Flask-Login requires is_active; route it to our column
    @property
    def is_active(self):
        return self.active

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_superadmin(self) -> bool:
        return self.role == "superadmin"


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


def _superadmin_count() -> int:
    return User.query.filter_by(role="superadmin", active=True).count()


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key_size = db.Column(db.Integer, default=2048)
    country = db.Column(db.String(2), default="US")
    state = db.Column(db.String(128), default="")
    city = db.Column(db.String(128), default="")
    org_name = db.Column(db.String(256), default="")
    org_unit = db.Column(db.String(256), default="")
    email = db.Column(db.String(256), default="")


class IntermediateCert(db.Model):
    __tablename__ = "intermediate_cert"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(256), nullable=False)
    pem_data = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def parsed_cert(self):
        try:
            return x509.load_pem_x509_certificate(self.pem_data.encode())
        except Exception:
            return None

    @property
    def expiry_date(self):
        cert = self.parsed_cert
        if cert is None:
            return None
        try:
            exp = cert.not_valid_after_utc
        except AttributeError:
            exp = cert.not_valid_after
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        return exp

    @property
    def subject(self):
        cert = self.parsed_cert
        if cert is None:
            return "Unknown"
        try:
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except (IndexError, Exception):
            return str(cert.subject)

    @property
    def is_root(self):
        cert = self.parsed_cert
        if cert is None:
            return False
        try:
            return cert.subject == cert.issuer
        except Exception:
            return False


class Certificate(db.Model):
    __tablename__ = "certificate"

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(256), nullable=False)
    san_domains = db.Column(db.Text, default="[]")  # JSON list
    key_size = db.Column(db.Integer, default=2048)
    private_key_pem = db.Column(db.Text)
    csr_pem = db.Column(db.Text)
    signed_cert_pem = db.Column(db.Text)
    status = db.Column(db.String(32), default="pending_signing")
    expiry_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    country = db.Column(db.String(2), default="US")
    state = db.Column(db.String(128), default="")
    city = db.Column(db.String(128), default="")
    org_name = db.Column(db.String(256), default="")
    org_unit = db.Column(db.String(256), default="")
    email = db.Column(db.String(256), default="")

    @property
    def san_list(self):
        try:
            return json.loads(self.san_domains or "[]")
        except (json.JSONDecodeError, TypeError):
            return []

    @property
    def days_until_expiry(self):
        if self.expiry_date is None:
            return None
        now = datetime.now(timezone.utc)
        exp = self.expiry_date
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        delta = exp - now
        return delta.days

    @property
    def status_label(self):
        if self.status == "active":
            days = self.days_until_expiry
            if days is not None and days < 0:
                return "expired"
            return "active"
        return self.status


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def get_settings():
    settings = Settings.query.first()
    if settings is None:
        settings = Settings()
        db.session.add(settings)
        db.session.commit()
    return settings


def generate_key_and_csr(domain, san_list, key_size, country, state, city, org_name, org_unit, email):
    """Generate RSA private key and CSR. Returns (private_key_pem, csr_pem) as strings."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    name_attrs = []
    if country:
        name_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2]))
    if state:
        name_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if city:
        name_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, city))
    if org_name:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name))
    if org_unit:
        name_attrs.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit))
    if email:
        name_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    name_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, domain))

    subject = x509.Name(name_attrs)

    # Build SAN list
    san_names = [x509.DNSName(domain)]
    for san in san_list:
        san = san.strip()
        if san and san != domain:
            san_names.append(x509.DNSName(san))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return private_key_pem, csr_pem


def parse_cert_expiry(cert_pem):
    """Parse x509 cert PEM and return expiry datetime (timezone-aware UTC)."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    try:
        exp = cert.not_valid_after_utc
    except AttributeError:
        exp = cert.not_valid_after
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    return exp


def create_pkcs12(cert_pem, key_pem, intermediates_pem_list, password):
    """Create PKCS#12 bundle. Returns bytes."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)

    cas = []
    for pem in intermediates_pem_list:
        if pem and pem.strip():
            try:
                cas.append(x509.load_pem_x509_certificate(pem.encode()))
            except Exception:
                pass

    if isinstance(password, str):
        password = password.encode()

    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=None,
        key=key,
        cert=cert,
        cas=cas if cas else None,
        encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption(),
    )
    return p12_bytes


def create_jks(cert_pem, key_pem, intermediates_pem_list, store_password, alias="certificate"):
    """Create JKS keystore. Returns bytes."""
    import jks

    # Convert private key to PKCS8 DER
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    key_der = key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Convert certs to DER
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    cert_chain_der = [cert_der]
    for pem in intermediates_pem_list:
        if pem and pem.strip():
            try:
                ic = x509.load_pem_x509_certificate(pem.encode())
                cert_chain_der.append(ic.public_bytes(serialization.Encoding.DER))
            except Exception:
                pass

    entry = jks.PrivateKeyEntry.new(alias, cert_chain_der, key_der)

    if isinstance(store_password, bytes):
        store_password = store_password.decode()

    keystore = jks.KeyStore.new("jks", [entry])

    with tempfile.NamedTemporaryFile(suffix=".jks", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        keystore.save(tmp_path, store_password)
        with open(tmp_path, "rb") as f:
            jks_bytes = f.read()
    finally:
        os.unlink(tmp_path)

    return jks_bytes


def create_p7b(cert_pem_list):
    """Create PKCS#7 P7B bundle from list of PEM strings. Returns bytes or None."""
    try:
        # Write all certs to a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp_in:
            for pem in cert_pem_list:
                if pem and pem.strip():
                    tmp_in.write(pem)
                    if not pem.endswith("\n"):
                        tmp_in.write("\n")
            tmp_in_path = tmp_in.name

        with tempfile.NamedTemporaryFile(suffix=".p7b", delete=False) as tmp_out:
            tmp_out_path = tmp_out.name

        result = subprocess.run(
            ["openssl", "crl2pkcs7", "-nocrl", "-certfile", tmp_in_path, "-out", tmp_out_path, "-outform", "DER"],
            capture_output=True,
            timeout=15,
        )

        if result.returncode != 0:
            return None

        with open(tmp_out_path, "rb") as f:
            p7b_bytes = f.read()

        return p7b_bytes
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return None
    finally:
        try:
            os.unlink(tmp_in_path)
        except Exception:
            pass
        try:
            os.unlink(tmp_out_path)
        except Exception:
            pass


def create_components_zip(domain, cert_pem, key_pem, intermediates_pem_list, csr_pem=None):
    """Create a ZIP of component PEM files. Returns BytesIO.

    Contents:
      private_key.pem      — RSA private key only
      certificate.pem      — signed certificate only
      chain.pem            — intermediates concatenated (no cert, no key)
                             use as Apache SSLCACertificateFile
      fullchain.pem        — signed cert + intermediates (no private key)
                             use as nginx ssl_certificate or Apache SSLCertificateFile
      certificate.csr      — original CSR (if available)
    """
    active_intermediates = [p for p in intermediates_pem_list if p and p.strip()]

    buf = BytesIO()
    with ZipFile(buf, "w") as zf:
        zf.writestr("private_key.pem", key_pem)
        zf.writestr("certificate.pem", cert_pem)

        if active_intermediates:
            zf.writestr(
                "chain.pem",
                "\n".join(p.strip() for p in active_intermediates) + "\n",
            )

        fullchain_parts = [cert_pem] + active_intermediates
        zf.writestr("fullchain.pem", "\n".join(p.strip() for p in fullchain_parts) + "\n")

        if csr_pem:
            zf.writestr("certificate.csr", csr_pem)

    buf.seek(0)
    return buf


def get_intermediates_ordered():
    """Return intermediate certs sorted by order ascending."""
    return IntermediateCert.query.order_by(IntermediateCert.order.asc()).all()


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def superadmin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_superadmin:
            flash("Superadmin access required.", "error")
            return redirect(url_for("certificates"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


# ---------------------------------------------------------------------------
# Before-request hook
# ---------------------------------------------------------------------------

@app.before_request
def first_run_check():
    """Redirect to setup page if no users exist yet."""
    if request.endpoint in (None, "setup", "login", "logout", "static"):
        return
    if User.query.count() == 0:
        return redirect(url_for("setup"))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    return redirect(url_for("certificates"))


# ---- Auth routes ----

@app.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run setup — only accessible when no users exist."""
    if User.query.count() > 0:
        return redirect(url_for("login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        error = None
        if not username:
            error = "Username is required."
        elif not email:
            error = "Email is required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        if error:
            flash(error, "error")
            return render_template("setup.html")
        user = User(username=username, email=email, role="superadmin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash(f"Welcome, {username}! Your admin account has been created.", "success")
        return redirect(url_for("certificates"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("certificates"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")
        if not user.active:
            flash("This account has been deactivated.", "error")
            return render_template("login.html")
        login_user(user, remember=remember)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("certificates"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# ---- User management routes ----

@app.route("/users")
@superadmin_required
def users():
    all_users = User.query.order_by(User.created_at.asc()).all()
    return render_template("users.html", users=all_users)


@app.route("/users/new", methods=["GET", "POST"])
@superadmin_required
def user_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "user")
        if role not in ("superadmin", "user"):
            role = "user"
        error = None
        if not username:
            error = "Username is required."
        elif not email:
            error = "Email is required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."
        elif User.query.filter_by(username=username).first():
            error = f"Username '{username}' is already taken."
        elif User.query.filter_by(email=email).first():
            error = f"Email '{email}' is already registered."
        if error:
            flash(error, "error")
            return render_template("user_form.html", user=None, roles=["superadmin", "user"])
        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("users"))
    return render_template("user_form.html", user=None, roles=["superadmin", "user"])


@app.route("/users/<int:user_id>/edit")
@superadmin_required
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("user_form.html", user=user, roles=["superadmin", "user"])


@app.route("/users/<int:user_id>/update", methods=["POST"])
@superadmin_required
def user_update(user_id):
    user = User.query.get_or_404(user_id)
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    role     = request.form.get("role", "user")
    active   = request.form.get("active") == "1"
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    if role not in ("superadmin", "user"):
        role = "user"
    error = None
    if not username:
        error = "Username is required."
    elif not email:
        error = "Email is required."
    else:
        dup_user  = User.query.filter(User.username == username, User.id != user_id).first()
        dup_email = User.query.filter(User.email == email,     User.id != user_id).first()
        if dup_user:
            error = f"Username '{username}' is already taken."
        elif dup_email:
            error = f"Email '{email}' is already registered."
    # Prevent removing the last active superadmin
    if not error and (role != "superadmin" or not active):
        if user.role == "superadmin" and user.active:
            if _superadmin_count() <= 1:
                error = "Cannot demote or deactivate the last active superadmin."
    if error:
        flash(error, "error")
        return render_template("user_form.html", user=user, roles=["superadmin", "user"])
    if password:
        if len(password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("user_form.html", user=user, roles=["superadmin", "user"])
        user.set_password(password)
    user.username = username
    user.email    = email
    user.role     = role
    user.active   = active
    db.session.commit()
    flash(f"User '{username}' updated.", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@superadmin_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("users"))
    if user.role == "superadmin" and _superadmin_count() <= 1:
        flash("Cannot delete the last superadmin.", "error")
        return redirect(url_for("users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("users"))


# ---- Certificates ----

@app.route("/certificates")
@login_required
def certificates():
    certs = Certificate.query.order_by(Certificate.created_at.desc()).all()
    return render_template("certificates.html", certs=certs)


@app.route("/certificates/new", methods=["GET", "POST"])
@login_required
def certificate_new():
    settings = get_settings()
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if not domain:
            flash("Domain is required.", "error")
            return render_template("cert_new.html", settings=settings)

        san_raw = request.form.get("san_domains", "").strip()
        san_list = [s.strip() for s in san_raw.splitlines() if s.strip()]

        try:
            key_size = int(request.form.get("key_size", settings.key_size))
        except (ValueError, TypeError):
            key_size = 2048

        country = request.form.get("country", settings.country or "").strip()
        state = request.form.get("state", settings.state or "").strip()
        city = request.form.get("city", settings.city or "").strip()
        org_name = request.form.get("org_name", settings.org_name or "").strip()
        org_unit = request.form.get("org_unit", settings.org_unit or "").strip()
        email = request.form.get("email", settings.email or "").strip()

        try:
            private_key_pem, csr_pem = generate_key_and_csr(
                domain, san_list, key_size, country, state, city, org_name, org_unit, email
            )
        except Exception as e:
            flash(f"Error generating key/CSR: {e}", "error")
            return render_template("cert_new.html", settings=settings)

        cert = Certificate(
            domain=domain,
            san_domains=json.dumps(san_list),
            key_size=key_size,
            private_key_pem=private_key_pem,
            csr_pem=csr_pem,
            status="pending_signing",
            country=country,
            state=state,
            city=city,
            org_name=org_name,
            org_unit=org_unit,
            email=email,
        )
        db.session.add(cert)
        db.session.commit()
        flash(f"RSA key and CSR generated for {domain}.", "success")
        return redirect(url_for("certificate_detail", cert_id=cert.id))

    return render_template("cert_new.html", settings=settings)


@app.route("/certificates/<int:cert_id>")
@login_required
def certificate_detail(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    intermediates = get_intermediates_ordered()
    return render_template("cert_detail.html", cert=cert, intermediates=intermediates)


@app.route("/certificates/<int:cert_id>/upload", methods=["POST"])
@login_required
def certificate_upload(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    signed_pem = request.form.get("signed_cert_pem", "").strip()
    if not signed_pem:
        flash("No certificate PEM provided.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    try:
        expiry = parse_cert_expiry(signed_pem)
    except Exception as e:
        flash(f"Invalid certificate PEM: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    cert.signed_cert_pem = signed_pem
    cert.status = "active"
    # Store as naive UTC for SQLite compatibility
    if expiry.tzinfo is not None:
        expiry = expiry.replace(tzinfo=None)
    cert.expiry_date = expiry
    db.session.commit()
    flash("Signed certificate uploaded successfully.", "success")
    return redirect(url_for("certificate_detail", cert_id=cert_id))


@app.route("/certificates/<int:cert_id>/delete", methods=["POST"])
@login_required
def certificate_delete(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    domain = cert.domain
    db.session.delete(cert)
    db.session.commit()
    flash(f"Certificate for {domain} deleted.", "success")
    return redirect(url_for("certificates"))


# ---- Certificate Downloads ----

@app.route("/certificates/<int:cert_id>/download/csr")
@login_required
def download_csr(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.csr_pem:
        flash("No CSR available.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))
    buf = BytesIO(cert.csr_pem.encode())
    return send_file(
        buf,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{cert.domain}.csr",
    )


@app.route("/certificates/<int:cert_id>/download/fullchain")
@login_required
def download_fullchain(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_intermediates_ordered()
    parts = [cert.private_key_pem, cert.signed_cert_pem]
    for ic in intermediates:
        parts.append(ic.pem_data)

    fullchain = "\n".join(p.strip() for p in parts if p and p.strip()) + "\n"
    buf = BytesIO(fullchain.encode())
    return send_file(
        buf,
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=f"{cert.domain}-fullchain.pem",
    )


@app.route("/certificates/<int:cert_id>/download/components")
@login_required
def download_components(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_intermediates_ordered()
    intermediates_pems = [ic.pem_data for ic in intermediates]

    buf = create_components_zip(
        cert.domain,
        cert.signed_cert_pem,
        cert.private_key_pem,
        intermediates_pems,
        csr_pem=cert.csr_pem,
    )
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"{cert.domain}-certs.zip",
    )


@app.route("/certificates/<int:cert_id>/download/pkcs12", methods=["POST"])
@login_required
def download_pkcs12(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    password = request.form.get("password", "")

    intermediates = get_intermediates_ordered()
    intermediates_pems = [ic.pem_data for ic in intermediates]

    try:
        p12_bytes = create_pkcs12(cert.signed_cert_pem, cert.private_key_pem, intermediates_pems, password)
    except Exception as e:
        flash(f"Error creating PKCS#12: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(p12_bytes)
    return send_file(
        buf,
        mimetype="application/x-pkcs12",
        as_attachment=True,
        download_name=f"{cert.domain}.p12",
    )


@app.route("/certificates/<int:cert_id>/download/jks", methods=["POST"])
@login_required
def download_jks(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    password = request.form.get("password", "changeit")
    alias = request.form.get("alias", "certificate").strip() or "certificate"

    intermediates = get_intermediates_ordered()
    intermediates_pems = [ic.pem_data for ic in intermediates]

    try:
        jks_bytes = create_jks(cert.signed_cert_pem, cert.private_key_pem, intermediates_pems, password, alias=alias)
    except Exception as e:
        flash(f"Error creating JKS: {e}", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(jks_bytes)
    return send_file(
        buf,
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=f"{cert.domain}.jks",
    )


@app.route("/certificates/<int:cert_id>/download/p7b")
@login_required
def download_p7b(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    if not cert.signed_cert_pem:
        flash("Certificate not yet signed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    intermediates = get_intermediates_ordered()
    pem_list = [cert.signed_cert_pem] + [ic.pem_data for ic in intermediates]

    p7b_bytes = create_p7b(pem_list)
    if p7b_bytes is None:
        flash("P7B creation failed. Ensure OpenSSL is installed.", "error")
        return redirect(url_for("certificate_detail", cert_id=cert_id))

    buf = BytesIO(p7b_bytes)
    return send_file(
        buf,
        mimetype="application/x-pkcs7-certificates",
        as_attachment=True,
        download_name=f"{cert.domain}.p7b",
    )


# ---- Settings ----

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    s = get_settings()
    if request.method == "POST":
        try:
            s.key_size = int(request.form.get("key_size", 2048))
        except (ValueError, TypeError):
            s.key_size = 2048
        s.country = request.form.get("country", "").strip()[:2]
        s.state = request.form.get("state", "").strip()
        s.city = request.form.get("city", "").strip()
        s.org_name = request.form.get("org_name", "").strip()
        s.org_unit = request.form.get("org_unit", "").strip()
        s.email = request.form.get("email", "").strip()
        db.session.commit()
        flash("Settings saved.", "success")
        return redirect(url_for("settings"))
    return render_template("settings.html", settings=s)


# ---- Intermediates ----

@app.route("/intermediates")
@login_required
def intermediates():
    certs = get_intermediates_ordered()
    return render_template("intermediates.html", certs=certs)


@app.route("/intermediates/new", methods=["POST"])
@login_required
def intermediate_new():
    name = request.form.get("name", "").strip()
    pem_data = request.form.get("pem_data", "").strip()
    try:
        order = int(request.form.get("order", 0))
    except (ValueError, TypeError):
        order = 0

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("intermediate_form_new"))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("intermediate_form_new"))

    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("intermediate_form_new"))

    ic = IntermediateCert(name=name, pem_data=pem_data, order=order)
    db.session.add(ic)
    db.session.commit()
    flash(f"Certificate '{name}' added.", "success")
    return redirect(url_for("intermediates"))


@app.route("/intermediates/new-form")
@login_required
def intermediate_form_new():
    return render_template("intermediate_form.html", cert=None, action=url_for("intermediate_new"))


@app.route("/intermediates/<int:ic_id>/edit")
@login_required
def intermediate_edit(ic_id):
    ic = IntermediateCert.query.get_or_404(ic_id)
    return render_template("intermediate_form.html", cert=ic, action=url_for("intermediate_update", ic_id=ic_id))


@app.route("/intermediates/<int:ic_id>/update", methods=["POST"])
@login_required
def intermediate_update(ic_id):
    ic = IntermediateCert.query.get_or_404(ic_id)
    name = request.form.get("name", "").strip()
    pem_data = request.form.get("pem_data", "").strip()
    try:
        order = int(request.form.get("order", 0))
    except (ValueError, TypeError):
        order = 0

    if not name:
        flash("Name is required.", "error")
        return redirect(url_for("intermediate_edit", ic_id=ic_id))
    if not pem_data:
        flash("PEM data is required.", "error")
        return redirect(url_for("intermediate_edit", ic_id=ic_id))

    try:
        x509.load_pem_x509_certificate(pem_data.encode())
    except Exception as e:
        flash(f"Invalid PEM certificate data: {e}", "error")
        return redirect(url_for("intermediate_edit", ic_id=ic_id))

    ic.name = name
    ic.pem_data = pem_data
    ic.order = order
    db.session.commit()
    flash(f"Certificate '{name}' updated.", "success")
    return redirect(url_for("intermediates"))


@app.route("/intermediates/<int:ic_id>/delete", methods=["POST"])
@login_required
def intermediate_delete(ic_id):
    ic = IntermediateCert.query.get_or_404(ic_id)
    name = ic.name
    db.session.delete(ic)
    db.session.commit()
    flash(f"Certificate '{name}' deleted.", "success")
    return redirect(url_for("intermediates"))


@app.route("/intermediates/reorder", methods=["POST"])
@login_required
def intermediate_reorder():
    data = request.get_json()
    if not data or not isinstance(data, list):
        return {"error": "Invalid data"}, 400
    for item in data:
        ic = IntermediateCert.query.get(item.get("id"))
        if ic is not None:
            ic.order = item.get("order", 0)
    db.session.commit()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

with app.app_context():
    db.create_all()
    if Settings.query.first() is None:
        default_settings = Settings(key_size=2048)
        db.session.add(default_settings)
        db.session.commit()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
