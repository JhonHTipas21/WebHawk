# Repository Security: Branch Protection Rules

WebHawk strictly enforces an automated offensive testing pipeline (AppSec CI Security Gates). To ensure these tests cannot be bypassed, the repository administrator MUST configure Branch Protection Rules on the `main` branch.

## How to Configure

1. Navigate to **Settings** > **Branches** in the GitHub repository.
2. Under "Branch protection rules", click **Add branch protection rule** (or edit the existing rule for `main`).
3. Set the **Branch name pattern** to `main`.
4. Check **Require a pull request before merging**.
5. Check **Require status checks to pass before merging**.
6. In the search bar for status checks, search for and select the following explicitly required checks:
   - `Offensive Security Testing`
   - `SAST & Configuration Security`
   - `SCA and Unit Tests`
7. Check **Do not allow bypassing the above settings** to ensure even administrators cannot push broken cryptography.
8. Click **Create** or **Save changes**.

## Threat Model Enforcement
The `Offensive Security Testing` job isolates the WebHawk pipeline and hurls 10 simulated AppSec attack vectors at it (Invalid Signatures, Timing Attacks, Replay Attacks, etc.). 

If this job fails, it indicates a critical cryptographic or logic flaw has been introduced that allows an attack to succeed. **Under no circumstances should a PR be merged if this gate fails.**
