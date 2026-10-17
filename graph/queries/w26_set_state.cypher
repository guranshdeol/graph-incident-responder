// W26 set an instance's state (sandbox executor for start_instance; discovery overwrites it on live). Params: $rid, $state
MATCH (r:Resource {rid: $rid})
SET r.state = $state
RETURN r.rid AS rid
