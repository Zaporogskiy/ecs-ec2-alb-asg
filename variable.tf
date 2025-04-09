variable "project_name" {
  default = "education"

}

variable "ultravox_api_key" {
  sensitive = true
}

variable "human_agent_callerid" {
  sensitive = true
}

variable "human_agent_trunk" {
  sensitive = true
}

variable "human_agent_number" {
  sensitive = true
}