# Synthetic configuration for static security analysis only.
# A restricted CIDR does not establish overall infrastructure security.

resource "aws_security_group" "lab_ssh" {
  name        = "iac-security-gate-lab"
  description = "Synthetic restricted SSH example"

  ingress {
    description = "SSH limited to a private lab subnet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.10.10.0/24"]
  }
}
