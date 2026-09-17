# BIG-IP License Automation

This is a standalone BIG-IP licensing utility. It is completely separate from
the upgrade project and is not imported or called by `make upgrade-node`.

The utility supports:

- Generating a BIG-IP dossier without changing the device.
- Retrieving the F5 Activation Service EULA.
- Explicit EULA acceptance.
- Activating a registration key through F5.
- Applying the signed license with `reloadlic`.
- Verifying the BIG-IP license endpoint afterward.

## Setup

```bash
cd /Users/v.gatla/Downloads/LicenseAutomation
make setup
```

## Required environment

```bash
export BIGIP_HOST="10.10.10.10"
export BIGIP_USER="admin"
export F5_REGISTRATION_KEY="XXXXX-XXXXX-XXXXX-XXXXX-XXXXXXX"
```

Set `BIGIP_PASS` for non-interactive execution, or leave it unset for a
secure interactive password prompt.

TLS certificate verification is disabled by default for compatibility with
BIG-IP management certificates. Use `--verify-tls` when the management and
Activation Service certificates are trusted.

The public activation endpoint is used by default:

```text
https://activate.f5.com/license/services/urn:com.f5.license.v5b.ActivationService
```

Override it only when F5 provides a supported alternate endpoint:

```bash
export F5_ACTIVATION_URL="https://activate.f5.com/license/services/"
```

## Generate a dossier only

This does not contact the F5 Activation Service and does not change the
license on BIG-IP:

```bash
make dossier
```

## Activate and apply a license

This performs the destructive licensing actions only after explicit EULA
acceptance:

```bash
make activate
```

The activation sequence is:

```text
BIG-IP get_dossier
  -> F5 getEULA
  -> operator EULA confirmation
  -> F5 activate
  -> write /config/bigip.license
  -> /usr/bin/reloadlic
  -> verify /mgmt/tm/sys/license
```

The public F5 service currently publishes an Apache Axis `getLicense` SOAP
operation. Its RPC responses may contain `href`/`multiRef` references; the
client resolves those references before extracting the EULA and signed
license. This follows the same two-step sequence described in K000161807:
request the EULA, then submit the accepted EULA to receive the signed license.

The BIG-IP client attempts token authentication through
`/mgmt/shared/authn/login` and falls back to Basic authentication if token
authentication is unavailable. After activation, it verifies the returned
registration key when BIG-IP includes it in the license response.

Never commit credentials or registration keys to source control. Review the
F5 licensing requirements and registration-key status before activation.
