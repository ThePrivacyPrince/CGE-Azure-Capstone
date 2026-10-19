# The stage contract: what discovery found and what activation is closing.
# `terraform output` here doubles as a live plan-coverage inventory — the first
# artifact every assessment asks for, free.

output "current_plan_tiers" {
  description = "Every baseline Defender plan in every governed subscription (\"<subscription>/<plan>\") and its tier as discovered this run."
  value       = local.current_tier
}

output "activation_needed" {
  description = "The gap map this apply closes. Empty means the baseline is fully met."
  value       = local.activation_needed
}

output "governed_subscriptions" {
  description = "Subscriptions discovered under the management group this run."
  value       = sort(local.subscriptions)
}
