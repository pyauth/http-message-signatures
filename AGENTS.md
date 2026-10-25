# Agent guidance

- Do not impose constraints on HTTP messages unless those constraints concern the integrity or authenticity of the signature. Application-level validation of message content belongs to the caller.
- Do not edit `Changes.rst`; it is generated automatically by the release machinery.
- Do not customize Sphinx autodoc configuration or directives to list individual symbols or member lists. All autodoc configuration must be generic.
- Public APIs must be documented. Private modules, classes, and helper functions must use an underscore prefix.
- Do not define `__all__` in project modules without the user's explicit approval.
