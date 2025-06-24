from fpdf import FPDF
import os

class CertificatePDF(FPDF):
    def header(self):
        """ Add a decorative border """
        self.set_line_width(2)
        self.rect(5, 5, 287, 200)

    def footer(self):
        """ Footer with blockchain verification note """
        self.set_y(-15)
        self.set_font("Arial", "I", 10)
        self.cell(0, 10, "Verify this certificate using the certificate hash on our verification page.", align="C")

def create_certificate_pdf(name, course, date, cert_hash, signature_img="static/sign.png", seal_img="static/seal.png"):
    pdf = CertificatePDF(orientation='L', unit='mm', format='A4')
    pdf.add_page()

    # Title
    pdf.set_font("Arial", 'B', 28)
    pdf.cell(0, 20, "CERTIFICATE OF COMPLETION", ln=True, align='C')
    pdf.ln(10)

    # Presented To
    pdf.set_font("Arial", 'I', 18)
    pdf.cell(0, 10, "This certificate is proudly presented to:", ln=True, align='C')
    pdf.ln(5)

    # Recipient Name
    pdf.set_font("Arial", 'B', 24)
    pdf.cell(0, 15, name, ln=True, align='C')
    pdf.ln(10)

    # Course Name
    pdf.set_font("Arial", '', 16)
    pdf.cell(0, 10, f"For successfully completing the course:", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(0, 10, course, ln=True, align='C')
    pdf.ln(10)

    # Date
    pdf.set_font("Arial", '', 14)
    pdf.cell(0, 10, f"Date of Completion: {date}", ln=True, align='C')
    pdf.ln(10)

    # Certificate Hash
    pdf.set_font("Courier", '', 12)
    pdf.cell(0, 10, f"Certificate Hash: {cert_hash}", ln=True, align='C')
    pdf.ln(15)

    # Adding Signature & Seal Images
    if os.path.exists(signature_img):
        pdf.image(signature_img, x=90, y=140, w=20, h=20)  # Signature image

    if os.path.exists(seal_img):
        pdf.image(seal_img, x=200, y=140, w=30, h=30)  # Seal image

    # Signature & Seal Lines
    pdf.line(60, 160, 120, 160)  # Signature line
    pdf.line(180, 160, 240, 160)  # Seal line
    pdf.set_font("Arial", 'I', 12)
    pdf.text(75, 165, "Authorized Signature")
    pdf.text(195, 165, "Official Seal")

    # Save PDF
    cert_dir = "certificates"
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)
    cert_path = os.path.join(cert_dir, f"{cert_hash}.pdf")
    pdf.output(cert_path)

    print(f"✅ Certificate generated successfully: {cert_path}")
    return cert_path

# Example usage
# create_certificate_pdf("John Doe", "Python Programming", "March 17, 2025", "0xabc123xyz", "signature.png", "seal.png")
