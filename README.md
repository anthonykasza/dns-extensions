A proof-of-concept demonstrating scriptland parsing and event routing for all DNS extensions.

See [ssl-extensions](https://github.com/anthonykasza/ssl-extensions).

This package is incomplete and needs 2 things:
1. It requires a new event to be defined and raised by the DNS analyzer just before the existing EDNS parsing
2. It requires definitions for parsed types and parser functions
