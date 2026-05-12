# Final Launch Checklist

## Before publishing

- Confirm you are working from the standalone root at `C:\UEG_PRODUCT`
- Confirm the release archives exist in `dist/`
- Confirm `checksums.txt` exists in `dist/`
- Confirm `examples/quick_demo.md` is accurate
- Confirm `launch/landing-page.html` has your real download URLs and contact address

## GitHub release

- Create the GitHub repository for UEG if it does not already exist
- Push the contents of `C:\UEG_PRODUCT` to the new repository
- Create a release tag that matches the binary version you are publishing
- Draft the release using `launch/GITHUB_RELEASE_NOTES.md`
- Upload the four platform archives from `dist/`
- Upload `checksums.txt`
- Publish the release

## Landing page

- Deploy `launch/landing-page.html` to your preferred static host
- Replace placeholder download URLs with the real GitHub release URLs
- Replace the placeholder contact email with your real email
- Add a visible link to the GitHub release page
- Test all buttons after deployment

## Product Hunt

- Use a personal Product Hunt account
- Confirm that the account currently has posting access
- Create a draft or schedule the launch before launch day
- Add the main product URL and the download link
- Add up to 3 matching categories
- Paste the submission copy from `launch/PRODUCT_HUNT_SUBMISSION.md`
- Upload the screenshots and GIF from `launch/SCREENSHOT_PLAN.md`
- Add the maker comment and first comment
- Publish when the landing page and GitHub release are already live

## Outreach

- Post the launch on LinkedIn
- Post the X/Twitter version
- Submit Show HN
- Post the Reddit versions where appropriate
- Reply to early comments with demo links, not marketing fluff

## After launch

- Watch which asset people click first: GitHub release, quick demo, or landing page CTA
- Save feedback about missing features separately from launch bugs
- If a real bug is reported, reproduce it before touching the core
