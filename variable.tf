variable "project_name" {
  default = "ai-calling-transfer"
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