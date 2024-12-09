module DNS::EXTENSIONS;

export {
  global reserved: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_reserved);
  global llq: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_llq);
  global update_lease: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_update_lease);
  global nsid: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_nsid);
  global dau: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_dau);
  global dhu: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_dhu);
  global n3u: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_n3u);
  global edns_client_subnet: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_client_subnet);
  global edns_expire: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_expire);
  global cookie: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_cookie);
  global edns_tcp_keepalive: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_tcp_keepalive);
  global padding: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_padding);
  global chain: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_chain);
  global edns_key_tag: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_key_tag);
  global extended_dns_error: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_extended_dns_error);
  global edns_client_tag: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_client_tag);
  global edns_server_tag: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_edns_server_tag);
  global report_channel: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_report_channel);
  global zoneversion: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_zoneversion);
  global unassigned: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_unassigned);
  global umbrella_ident: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_umbrella_ident);
  global device_id: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_device_id);
  global reserved_local_experimental: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_reserved_local_experimental);
  global reserved_future_expansion: event(c: connection, is_query: bool, result: DNS::EXTENSIONS::ParseResult_reserved_future_expansion);
}
