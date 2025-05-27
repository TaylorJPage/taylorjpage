variable "ami_id" {}
variable "instance_type" {}
variable "security_group_id" {}
variable "subnet_id" {}
variable "ebs_size" {
  default = 8
}

variable "desired_capacity" {
  default = 2
}
variable "min_size" {
  default = 1
}
variable "max_size" {
  default = 3
}
