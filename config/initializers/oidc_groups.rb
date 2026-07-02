# Loads the OIDC group → account mapping (see config/oidc_groups.yml) into
# Rails.application.config.x.oidc_groups, keyed by group name. Read via
# Oidc::GroupMap. Tests may override this value directly.
config_file = Rails.root.join("config/oidc_groups.yml")

groups =
  if config_file.exist?
    (YAML.load_file(config_file) || {}).fetch("groups", {}) || {}
  else
    {}
  end

Rails.application.config.x.oidc_groups = groups.deep_stringify_keys
