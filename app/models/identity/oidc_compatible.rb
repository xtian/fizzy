module Identity::OidcCompatible
  extend ActiveSupport::Concern

  class_methods do
    def find_or_create_from_oidc(auth_hash)
      provider = auth_hash&.provider
      subject = auth_hash&.uid
      email = auth_hash&.info&.email

      if subject.present? && email.present?
        if identity = find_by(oidc_provider: provider, oidc_subject: subject)
          identity.tap { |i| i.update!(email_address: email) if oidc_email_verified?(auth_hash) && i.email_address != email }
        else
          link_or_create_from_oidc(provider:, subject:, email:)
        end
      end
    end

    private
      def link_or_create_from_oidc(provider:, subject:, email:)
        if identity = find_by(email_address: email)
          identity.tap { |i| i.update!(oidc_provider: provider, oidc_subject: subject) }
        else
          create!(email_address: email, oidc_provider: provider, oidc_subject: subject)
        end
      end

      def oidc_email_verified?(auth_hash)
        ActiveModel::Type::Boolean.new.cast(auth_hash&.extra&.raw_info&.email_verified)
      end
  end

  # Reconciles account memberships against the OIDC group claim: grants access
  # to every mapped account named in the claim and revokes access to any managed
  # account that is no longer claimed. Only OIDC-managed accounts are touched.
  def reconcile_oidc_memberships(groups)
    Current.without_account do
      granted = grant_claimed_accounts(Oidc::GroupMap.admit(groups))
      revoke_unclaimed_accounts(except: granted)
    end
  end

  private
    def grant_claimed_accounts(groups)
      groups.filter_map do |group|
        if account = Oidc::GroupMap.account_for(group)
          join(account, role: Oidc::GroupMap.default_role(group))
          account
        end
      end
    end

    def revoke_unclaimed_accounts(except:)
      Oidc::GroupMap.managed_accounts.where.not(id: except.map(&:id)).find_each do |account|
        users.find_by(account: account)&.deactivate
      end
    end
end
