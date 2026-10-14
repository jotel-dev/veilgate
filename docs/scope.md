# VeilGate — Project Scope

## Project Overview
VeilGate is a privacy-first merchant checkout built on Zcash shielded payments for the Zecathon hackathon (Shielded Payments track).

- **Submission Deadline:** October 28, 2026, 23:59 UTC
- **Team:** Solo builder
- **Environment:** Windows
- **Primary Language:** Rust

---

## Hackathon Rules to Respect
- All code must be written during the build window.
- The repository must be open source at submission.
- Privacy leaks are disqualifying, not just point deductions.
- **Judging Criteria:** Privacy, Usefulness, Execution, Originality (Working beats ambitious).

---

## Must-Have (Core — Must Work End-to-End)
1. **Invoice Creation:** Create an invoice with an amount, an expiry time, and a unique invoice ID.
2. **Payment Link & QR Code:** Generate a payment link and QR code using a ZIP 321 payment request.
3. **Payment Detection & Confirmation:** Detect and confirm incoming shielded payments using a watch-only key, ensuring the server never holds spending authority.
4. **Merchant Dashboard:** Merchant dashboard displaying invoice statuses (pending, paid, expired).
5. **Privacy Documentation:** docs/privacy-model.md explaining what a public observer can see, what the merchant server can see, and what the checkout app itself exposes.

---

## Stretch Goals (Only If Must-Haves Are Finished and Tested)
1. **Selective Payment Receipts:** Limited to what the Zcash tooling actually supports.
2. **Observer vs. Merchant Demo:** A demo showing the public observer's view versus the merchant's view.

---

## Design Decision to Verify Before Building
- Match payments to invoices by generating a unique diversified address per invoice from the merchant's viewing key, rather than relying only on the encrypted memo.
- Verify in the librustzcash documentation that this works, and record the result in docs/privacy-model.md.

---

## Out of Scope
- Holding customer funds or spending keys on the server.
- Third-party analytics, tracking scripts, or any transparent-address fallback.
- Support for other cryptocurrencies.

---

## Privacy Rules for the Whole Project
- Never log personal data, addresses tied to customers, or seed phrases.
- No third-party calls from the checkout pages.
- Use shielded addresses only.

---

## Schedule (Milestones)
- **Oct 14–15:** Setup, light client connection, key handling.
- **Oct 16–19:** Invoices, ZIP 321 links, payment detection.
- **Oct 20–21:** Dashboard and customer payment page.
- **Oct 22:** Privacy audit.
- **Oct 23–24:** End-to-end testing and edge cases.
- **Oct 25–26:** README, demo video, polish.
- **Oct 27:** Final review, make repo public, submit.
- **Oct 28:** Buffer only.
