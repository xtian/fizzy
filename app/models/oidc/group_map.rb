# Resolves OIDC `groups` claim values to the isolated Account each maps to.
#
# The allow-list and per-group metadata live in config/oidc_groups.yml (loaded
# into Rails.application.config.x.oidc_groups). Only groups present there are
# admitted; each mapped account is created on demand and stamped with its
# `oidc_group` so future logins resolve to the same account.
module Oidc
  class GroupMap
    class << self
      # The subset of the claimed groups that are mapped (allow-listed).
      def admit(groups)
        normalize(groups) & mappings.keys
      end

      # The Account a mapped group belongs to, creating it if necessary.
      def account_for(group)
        if config = mappings[group.to_s]
          Account.find_by(oidc_group: group) || create_account(group, config)
        end
      end

      def default_role(group)
        mappings.dig(group.to_s, "default_role").presence&.to_sym || :member
      end

      # Every account under OIDC management, used to revoke stale memberships.
      def managed_accounts
        Account.where.not(oidc_group: nil)
      end

      private
        def mappings
          Rails.application.config.x.oidc_groups || {}
        end

        def create_account(group, config)
          Current.without_account do
            Account.create!(name: config.fetch("account_name", group), oidc_group: group).tap do |account|
              account.users.create!(role: :system, name: "System")
            end
          end
        end

        # Groups may arrive as plain names or full paths/DNs (e.g. "/acme-eng");
        # match on the trailing segment.
        def normalize(groups)
          Array(groups).map { |group| group.to_s.split("/").last.to_s.strip }.uniq
        end
    end
  end
end
