import pypdf
from pypdf import PdfWriter, PdfReader
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Create a PDF with a link to a known malware test site
packet = io.BytesIO()
can = canvas.Canvas(packet, pagesize=letter)
can.drawString(100, 500, "This looks like a safe invoice.")
can.drawString(100, 480, "Click below to pay:")
# The link below is a Google Safe Browsing test URL (flags as malware)
can.drawString(100, 460, "http://testsafebrowsing.appspot.com/s/malware.html")
can.save()

packet.seek(0)
new_pdf = PdfReader(packet)
output = PdfWriter()
output.add_page(new_pdf.pages[0])

with open("trap_invoice.pdf", "wb") as f:
    output.write(f)

print("Created 'trap_invoice.pdf'. Upload this to your scanner!")
