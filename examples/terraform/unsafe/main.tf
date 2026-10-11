# Synthetic configuration for static security analysis only.
# This example is not intended for deployment.

resource "aws_security_group" "lab_ssh" {
  name        = "iac-security-gate-lab"
  description = "Synthetic SSH exposure example"

  ingress {
    description = "SSH open to every IPv4 address"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
