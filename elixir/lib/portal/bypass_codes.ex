defmodule Portal.BypassCodes do
  @moduledoc """
  Context for issuing, redeeming, and revoking `Portal.BypassCode`s.

  A bypass code temporarily lifts always-on / tunnel-lock enforcement for a
  single client. The plaintext is generated and shown to the issuing admin
  exactly once; only a salted SHA-256 hash is persisted. Every redemption is
  logged for the audit trail.
  """
  import Ecto.Query

  alias Portal.{BypassCode, Crypto, Safe}
  require Logger

  @salt_bytes 16
  @code_length 10
  @hash_algo :sha256

  @doc """
  Issues a new bypass code for `device`, scoped to `account`, valid for
  `valid_for_seconds` from now. Returns `{:ok, code, plaintext}` where
  `plaintext` is shown to the admin once and never stored.

  Options:
    * `:max_uses` (default 1)
    * `:reason` (free text, audit context)
    * `:issued_by_actor_id`
  """
  @spec issue(Portal.Account.t(), Portal.Device.t(), non_neg_integer(), keyword()) ::
          {:ok, BypassCode.t(), String.t()} | {:error, Ecto.Changeset.t()}
  def issue(%Portal.Account{} = account, %Portal.Device{} = device, valid_for_seconds, opts \\ []) do
    plaintext = Crypto.random_token(@code_length, generator: :numeric)
    salt = Crypto.random_token(@salt_bytes, encoder: :base64)
    hash = Crypto.hash(@hash_algo, plaintext <> salt)

    now = DateTime.utc_now()
    expires_at = DateTime.add(now, valid_for_seconds, :second)

    attrs = %{
      account_id: account.id,
      device_id: device.id,
      issued_by_actor_id: opts[:issued_by_actor_id],
      secret_salt: salt,
      secret_hash: hash,
      reason: opts[:reason],
      expires_at: expires_at,
      max_uses: Keyword.get(opts, :max_uses, 1)
    }

    changeset = BypassCode.changeset(%BypassCode{}, attrs)

    case changeset |> Safe.unscoped() |> Safe.insert() do
      {:ok, code} ->
        Logger.info("Bypass code issued",
          account_id: account.id,
          device_id: device.id,
          bypass_code_id: code.id,
          issued_by_actor_id: opts[:issued_by_actor_id],
          expires_at: DateTime.to_iso8601(expires_at)
        )

        {:ok, code, plaintext}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Redeems `plaintext` for `device` in `account`. On success, increments the
  redemption count, records the timestamp, logs the redemption, and returns
  `{:ok, code}`. Returns `{:error, :invalid}` when no matching, redeemable code
  exists — the same error for "no such code", "expired", "revoked", and
  "exhausted", so redemption does not leak which codes exist.
  """
  @spec redeem(Portal.Account.t(), Portal.Device.t(), String.t()) ::
          {:ok, BypassCode.t()} | {:error, :invalid}
  def redeem(%Portal.Account{} = account, %Portal.Device{} = device, plaintext)
      when is_binary(plaintext) do
    now = DateTime.utc_now()

    candidates =
      from(c in BypassCode,
        where: c.account_id == ^account.id,
        where: c.device_id == ^device.id,
        where: is_nil(c.revoked_at),
        where: c.expires_at > ^now,
        where: c.redeemed_count < c.max_uses
      )
      |> Safe.unscoped()
      |> Safe.all()

    case Enum.find(candidates, &code_matches?(&1, plaintext)) do
      nil ->
        Logger.info("Bypass code redemption failed",
          account_id: account.id,
          device_id: device.id
        )

        {:error, :invalid}

      code ->
        do_redeem(code, now)
    end
  end

  defp code_matches?(%BypassCode{} = code, plaintext) do
    Crypto.equal?(@hash_algo, plaintext <> code.secret_salt, code.secret_hash)
  end

  defp do_redeem(%BypassCode{} = code, now) do
    changeset =
      code
      |> Ecto.Changeset.change(%{
        redeemed_count: code.redeemed_count + 1,
        last_redeemed_at: now
      })

    case changeset |> Safe.unscoped() |> Safe.update() do
      {:ok, updated} ->
        Logger.info("Bypass code redeemed",
          account_id: code.account_id,
          device_id: code.device_id,
          bypass_code_id: code.id,
          redeemed_count: updated.redeemed_count,
          max_uses: updated.max_uses
        )

        {:ok, updated}

      {:error, _changeset} ->
        {:error, :invalid}
    end
  end

  @doc "Revokes a bypass code so it can no longer be redeemed."
  @spec revoke(BypassCode.t()) :: {:ok, BypassCode.t()} | {:error, Ecto.Changeset.t()}
  def revoke(%BypassCode{} = code) do
    result =
      code
      |> Ecto.Changeset.change(%{revoked_at: DateTime.utc_now()})
      |> Safe.unscoped()
      |> Safe.update()

    case result do
      {:ok, revoked} ->
        Logger.info("Bypass code revoked",
          account_id: code.account_id,
          device_id: code.device_id,
          bypass_code_id: code.id
        )

        {:ok, revoked}

      error ->
        error
    end
  end
end
