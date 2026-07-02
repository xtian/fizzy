class AddOidcSupport < ActiveRecord::Migration[8.2]
  def change
    add_column :identities, :oidc_subject, :string
    add_column :identities, :oidc_provider, :string
    add_index :identities, [ :oidc_provider, :oidc_subject ], unique: true

    add_column :accounts, :oidc_group, :string
    add_index :accounts, :oidc_group, unique: true
  end
end
