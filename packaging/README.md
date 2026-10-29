# Packaging

The release workflow renders these templates with each release's version, URLs and SHA-256 hashes
(`packaging/render.sh`). It attaches them to the release as `modelcheck-<tag>-packaging.tar.gz`, together with the
`ModelSafetyCheck.<version>.nupkg` .NET tool package. Publishing to the stores needs accounts and tokens that only
the maintainer has, so the workflow does not do it. Each store takes these steps:

## NuGet (`dotnet tool install -g ModelSafetyCheck`)

1. Create an API key on nuget.org scoped to the `ModelSafetyCheck` package (push new versions).
2. Download the `.nupkg` from the release, check it against `SHA256SUMS` (and its attestation, when the repository is
   public), then:
   ```bash
   dotnet nuget push ModelSafetyCheck.0.3.0.nupkg --api-key <key> --source https://api.nuget.org/v3/index.json
   ```
   Alternatively, store the key as a repository secret and add that command as a final step of `release.yml`.

## winget

1. Unpack `modelcheck-<tag>-packaging.tar.gz`. The manifests are in `winget/`.
2. Validate them: `winget validate --manifest winget/`, then test: `winget install --manifest winget/`.
3. Fork [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) and copy the three files to
   `manifests/<first letter of publisher>/<Publisher>/ModelSafetyCheck/<version>/`.
4. Open a pull request. Later versions can use `wingetcreate update <id> --version <v> --urls <zip urls> --submit`.

The package identifier is `<GitHub owner>.ModelSafetyCheck`; edit `winget/*.yaml` to choose another publisher name.

## Homebrew

1. Create a tap repository named `homebrew-tap` (Homebrew requires the `homebrew-` prefix).
2. Copy `homebrew/modelcheck.rb` to `Formula/modelcheck.rb` in it and push.
3. Users install with `brew install <owner>/tap/modelcheck`.

The formula covers macOS arm64 and Linux x64/arm64, which are the platforms the release builds.

## Rendering locally

```bash
packaging/render.sh v0.3.0 <dir with the release archives> anefiox/ModelSafetyCheck out/
```
