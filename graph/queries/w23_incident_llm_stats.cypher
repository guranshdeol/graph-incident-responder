// W23 per-investigation LLM usage on the incident (D16). Params: $id, $tokens_in, $tokens_out, $agent_calls
MATCH (i:Incident {id: $id})
SET i.tokens_in = $tokens_in, i.tokens_out = $tokens_out, i.agent_calls = $agent_calls
