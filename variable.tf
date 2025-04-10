variable "project_name" {
  default = "ai-calling-transfer"
}

variable "ultravox_api_key" {
  default   = "pQdBjaCr.GNzMJkqpoG40zsRY6BUdMns2ttyP4Yrc"
  sensitive = true
}

variable "human_agent_callerid" {
  default   = "+1234567890"
  sensitive = true
}

variable "human_agent_trunk" {
  default   = "Chris_Outbound"
  sensitive = true
}

variable "human_agent_number" {
  default   = "2856571975"
  sensitive = true
}