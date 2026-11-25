# Code signing

The Windows package is signed with **Azure Artifact Signing** (Microsoft's managed code-signing service, formerly
*Trusted Signing*). The release workflow signs `WafGateway.exe`, `wafctl.exe` and `Install.ps1`:

- **Signature:** Authenticode, with SHA-256 for both the file digest and the timestamp.
- **Timestamp:** from `http://timestamp.acs.microsoft.com`, so the signatures stay valid after the short-lived
  signing certificate expires.
- **Check:** the workflow checks every signature before it zips the package. A missing or invalid signature stops the
  release.
- **Credentials:** no secret is stored in GitHub. The workflow signs in to Azure with OpenID Connect, which gives it a
  short-lived token for one run.

Until the setup below is done, releases are built **unsigned**, and the workflow run shows a warning.

The Linux packages are not Authenticode-signed (Linux has no equivalent for these files). Each release has
`SHA256SUMS.txt` with the checksums of all packages.

## One-time setup

You need an Azure subscription and the rights to create resources and app registrations in its tenant.

1. **Create the signing account.**
   - In the Azure portal, register the resource provider **Microsoft.CodeSigning** for the subscription.
   - Create an **Artifact Signing account** in a region near you, for example West Europe.
   - Note its **endpoint**, for example `https://weu.codesigning.azure.net/`, and its **name**.
2. **Validate the publisher's identity.**
   - In the account, start an **identity validation** for the organization (FA-Soft), with the legal name and
     address as registered.
   - Microsoft checks it, which can take a few days.
   - Public trust is only offered to organizations in some countries; check that FA-Soft is eligible before paying for
     the account.
3. **Create a certificate profile.**
   - Make a profile of type **Public Trust**, based on the validated identity.
   - Note its **name**. The signed files show the validated name as publisher.
4. **Create the identity the workflow signs in as.**
   1. In Microsoft Entra ID, create an **app registration**, for example `waf-gateway-release-signing`.
   2. Under *Certificates & secrets > Federated credentials*, add a credential for GitHub Actions:
      - organization `FA-Soft`, repository `WAF`;
      - entity type **Environment**, environment `release`.

      The release job runs in that environment, so every tag uses the same subject:
      `repo:FA-Soft/WAF:environment:release`.
   3. Note the **tenant ID** and the app's **client ID**.
5. **Allow the identity to sign.** On the signing account (or only on the certificate profile), assign the role
   **Artifact Signing Certificate Profile Signer** to the app registration. That role is named *Trusted Signing
   Certificate Profile Signer* in older portals.
6. **Tell the workflow.** In the repository, open *Settings > Secrets and variables > Actions > Variables* and add
   these variables. None of them is secret.

   | Variable | Value |
   |---|---|
   | `AZURE_TENANT_ID` | the tenant ID |
   | `AZURE_CLIENT_ID` | the app registration's client ID |
   | `ARTIFACT_SIGNING_ENDPOINT` | the account's endpoint, e.g. `https://weu.codesigning.azure.net/` |
   | `ARTIFACT_SIGNING_ACCOUNT` | the signing account's name |
   | `ARTIFACT_SIGNING_PROFILE` | the certificate profile's name |

   You can also set them on the `release` environment (*Settings > Environments > release*). There you can add
   required reviewers, so a person approves each release before it is built and signed.
7. **Try it.**
   1. Run *Actions > Release > Run workflow* without a tag. It builds and signs, but does not publish.
   2. The step *Check the signatures* lists the signer and the timestamp of each file.
   3. Download the `package-win-x64` artifact and check it on Windows (below).

## Checking a signature

On Windows, open a file's *Properties > Digital Signatures*, or use PowerShell:

```powershell
Get-AuthenticodeSignature .\WafGateway.exe, .\wafctl.exe, .\Install.ps1 | Format-List Path, Status, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`.

Signing also counts toward the files' reputation with Microsoft Defender SmartScreen. A new publisher can still see a
SmartScreen notice for the first downloads, until the files have built up reputation.

## Signing by hand

The workflow is the normal way to sign. To sign a locally built package anyway:

1. Install the Artifact Signing client tools, as described in Microsoft's documentation.
2. Sign in with `az login` as an account with the signer role.
3. Run `signtool sign` with the Artifact Signing dlib and a `metadata.json` that names the endpoint, account and
   profile.

Microsoft's Artifact Signing documentation has the exact command for the current client version.
