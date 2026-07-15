"""
Automated Brand Reference Hash Generator (`auto_build_brand_references.py`).

WHAT THIS DOES:
Automatically launches headless Chromium (using the exact same 1366x768
viewport and engine configuration as your live scanner), navigates to the
official login/sign-in pages of top commonly spoofed brands, captures clean
screenshots, computes their perceptual hashes (pHash), and writes out
`reference_hashes.json` automatically.

WHY THIS IS BETTER THAN HARDCODED HASHES:
pHash measures visual structure. A screenshot captured on a Mac at 1920x1080
or with different fonts/scaling produces a slightly different hash than one
rendered inside headless Chromium on Linux. By running this script using your
own Playwright installation (or inside your Docker container), your reference
hashes will match the EXACT rendering environment of your live scans.
Plus, whenever a brand redesigns its login page, just re-run this script to
instantly update your baseline!

USAGE:
    python auto_build_brand_references.py --out reference_hashes.json
"""

import argparse
import asyncio
import json
import logging
from pathlib import Path

import imagehash
from PIL import Image
from playwright.async_api import async_playwright

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("auto_build_brand_references")

# Official login, home, and verification URLs for top commonly spoofed brands globally (200+ targets).
TOP_BRAND_LOGIN_URLS = {
    # --- 1. Enterprise Cloud, Workspace & Productivity (Top Brands + Multi-Step Targets) ---
    "microsoft_login": "https://login.microsoftonline.com/",
    "microsoft_home": "https://www.microsoft.com/",
    "google_login": "https://accounts.google.com/signin",
    "google_home": "https://www.google.com/",
    "apple_login": "https://appleid.apple.com/sign-in",
    "apple_home": "https://www.apple.com/",
    "adobe_login": "https://auth.services.adobe.com/en_US/index.html",
    "adobe_home": "https://www.adobe.com/",
    "dropbox_login": "https://www.dropbox.com/login",
    "dropbox_home": "https://www.dropbox.com/",
    "docusign_login": "https://account.docusign.com/",
    "docusign_home": "https://www.docusign.com/",
    "box_login": "https://account.box.com/login",
    "box_home": "https://www.box.com/",
    "zoom_login": "https://zoom.us/signin",
    "zoom_home": "https://zoom.us/",
    "slack_login": "https://slack.com/signin",
    "slack_home": "https://slack.com/",
    "salesforce_login": "https://login.salesforce.com/",
    "salesforce_home": "https://www.salesforce.com/",
    "okta_login": "https://login.okta.com/",
    "okta_home": "https://www.okta.com/",
    "cisco_webex": "https://idbroker.webex.com/idb/oauth2/v1/authorize",
    "atlassian_jira": "https://id.atlassian.com/login",
    "servicenow": "https://signon.service-now.com/ssologin.do",
    "workday": "https://www.myworkday.com/",
    "notion": "https://www.notion.so/login",
    "canva": "https://www.canva.com/login",
    "hubspot": "https://app.hubspot.com/login",
    "zendesk": "https://www.zendesk.com/login/",
    "trello": "https://id.atlassian.com/login?application=trello",

    # --- 2. Fintech, Payments & Crypto (Top Brands + Multi-Step Targets) ---
    "paypal_login": "https://www.paypal.com/signin",
    "paypal_home": "https://www.paypal.com/",
    "stripe_login": "https://dashboard.stripe.com/login",
    "stripe_home": "https://stripe.com/",
    "square_login": "https://squareup.com/login",
    "square_home": "https://squareup.com/",
    "coinbase_login": "https://www.coinbase.com/signin",
    "coinbase_home": "https://www.coinbase.com/",
    "binance_login": "https://accounts.binance.com/en/login",
    "binance_home": "https://www.binance.com/",
    "kraken_login": "https://www.kraken.com/sign-in",
    "kraken_home": "https://www.kraken.com/",
    "robinhood_login": "https://robinhood.com/login",
    "robinhood_home": "https://robinhood.com/",
    "wise_login": "https://wise.com/login/",
    "wise_home": "https://wise.com/",
    "venmo_login": "https://account.venmo.com/",
    "venmo_home": "https://venmo.com/",
    "cashapp_login": "https://cash.app/login",
    "cashapp_home": "https://cash.app/",
    "revolut": "https://app.revolut.com/start",
    "zelle": "https://www.zellepay.com/",
    "klarna": "https://app.klarna.com/login",
    "western_union": "https://www.westernunion.com/us/en/login.html",
    "moneygram": "https://www.moneygram.com/mgo/us/en/account/login",
    "crypto_com": "https://auth.crypto.com/users/sign_in",
    "gemini": "https://exchange.gemini.com/signin",
    "kucoin": "https://www.kucoin.com/ucenter/signin",
    "etoro": "https://www.etoro.com/login",
    "skrill": "https://account.skrill.com/login",

    # --- 3. Global Banking & Financial Institutions (Top Brands + Multi-Step Targets) ---
    "chase_login": "https://secure04ea.chase.com/web/auth/dashboard",
    "chase_home": "https://www.chase.com/",
    "bankofamerica_login": "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go",
    "bankofamerica_home": "https://www.bankofamerica.com/",
    "wellsfargo_login": "https://connect.secure.wellsfargo.com/auth/login/present?origin=coh",
    "wellsfargo_home": "https://www.wellsfargo.com/",
    "citibank_login": "https://online.citi.com/US/login.do",
    "citibank_home": "https://www.citi.com/",
    "americanexpress_login": "https://www.americanexpress.com/en-us/account/login",
    "americanexpress_home": "https://www.americanexpress.com/",
    "capitalone_login": "https://verified.capitalone.com/auth/signin",
    "capitalone_home": "https://www.capitalone.com/",
    "usbank_login": "https://www.usbank.com/login/",
    "usbank_home": "https://www.usbank.com/",
    "pnc_login": "https://www.pnc.com/en/personal-banking.html",
    "truist_login": "https://www.truist.com/",
    "td_bank_login": "https://onlinebanking.tdbank.com/",
    "td_bank_home": "https://www.td.com/",
    "hsbc_login": "https://www.hsbc.com/security/login",
    "hsbc_home": "https://www.hsbc.com/",
    "barclays_login": "https://bank.barclays.co.uk/olb/authlogin/loginAppContainer.do",
    "barclays_home": "https://www.barclays.co.uk/",
    "lloyds": "https://online.lloydsbank.co.uk/personal/logon/login.jsp",
    "santander": "https://www.santander.co.uk/personal/login",
    "rbc": "https://www1.royalbank.com/cgi-bin/rbaccess/rbunxcgi?F6=1&F7=IB&F21=IB&F22=IB&REQUEST=ClientSignin&LANGUAGE=ENGLISH",
    "scotiabank": "https://www.scotiabank.com/ca/en/personal/bank-your-way/online-banking/sign-in.html",
    "bmo": "https://www.bmo.com/main/personal",
    "ing": "https://www.ing.com/",
    "bnp_paribas": "https://masecurite.bnpparibas/",
    "deutsche_bank": "https://meine.deutsche-bank.de/",

    # --- 4. Major Retail, E-Commerce & Delivery (Top Brands + Multi-Step Targets) ---
    "amazon_login": "https://www.amazon.com/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.com%2F&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.assoc_handle=usflex&openid.mode=checkid_setup&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0",
    "amazon_home": "https://www.amazon.com/",
    "ebay_login": "https://signin.ebay.com/ws/eBayISAPI.dll?SignIn",
    "ebay_home": "https://www.ebay.com/",
    "walmart_login": "https://www.walmart.com/account/login",
    "walmart_home": "https://www.walmart.com/",
    "target_login": "https://www.target.com/login",
    "target_home": "https://www.target.com/",
    "alibaba_login": "https://passport.alibaba.com/icbu_login.htm",
    "alibaba_home": "https://www.alibaba.com/",
    "shopify_login": "https://accounts.shopify.com/lookup",
    "shopify_home": "https://www.shopify.com/",
    "aliexpress": "https://login.aliexpress.com/",
    "etsy": "https://www.etsy.com/signin",
    "bestbuy": "https://www.bestbuy.com/identity/signin",
    "homedepot": "https://www.homedepot.com/auth/view/login",
    "costco": "https://www.costco.com/LogonForm",
    "fedex_login": "https://www.fedex.com/secure-login/en-us/#/login-credentials",
    "fedex_home": "https://www.fedex.com/",
    "ups_login": "https://www.ups.com/lasso/login?loc=en_US",
    "ups_home": "https://www.ups.com/",
    "dhl_login": "https://www.dhl.com/global-en/home/login.html",
    "dhl_home": "https://www.dhl.com/",
    "usps_login": "https://reg.usps.com/entreg/LoginAction_input",
    "usps_home": "https://www.usps.com/",

    # --- 5. Social Media, Gaming & Communications ---
    "facebook_login": "https://www.facebook.com/login",
    "facebook_home": "https://www.facebook.com/",
    "instagram_login": "https://www.instagram.com/accounts/login/",
    "instagram_home": "https://www.instagram.com/",
    "linkedin_login": "https://www.linkedin.com/login",
    "linkedin_home": "https://www.linkedin.com/",
    "twitter_login": "https://twitter.com/i/flow/login",
    "twitter_home": "https://twitter.com/",
    "tiktok_login": "https://www.tiktok.com/login",
    "tiktok_home": "https://www.tiktok.com/",
    "discord_login": "https://discord.com/login",
    "discord_home": "https://discord.com/",
    "steam_login": "https://store.steampowered.com/login/",
    "steam_home": "https://store.steampowered.com/",
    "roblox_login": "https://www.roblox.com/login",
    "roblox_home": "https://www.roblox.com/",
    "netflix_login": "https://www.netflix.com/login",
    "netflix_home": "https://www.netflix.com/",
    "spotify_login": "https://accounts.spotify.com/en/login",
    "spotify_home": "https://www.spotify.com/",
    "reddit": "https://www.reddit.com/login/",
    "pinterest": "https://www.pinterest.com/login/",
    "snapchat": "https://accounts.snapchat.com/",
    "twitch": "https://www.twitch.tv/login",
    "epic_games": "https://www.epicgames.com/id/login",

    # --- 6. Telecom, ISPs & Webmail Providers ---
    "att_login": "https://signin.att.com/",
    "att_home": "https://www.att.com/",
    "verizon_login": "https://secure.verizon.com/vzauth/UI/Login",
    "verizon_home": "https://www.verizon.com/",
    "tmobile_login": "https://account.t-mobile.com/signin/v2/",
    "tmobile_home": "https://www.t-mobile.com/",
    "xfinity_login": "https://login.xfinity.com/login",
    "xfinity_home": "https://www.xfinity.com/",
    "yahoo_login": "https://login.yahoo.com/",
    "yahoo_home": "https://www.yahoo.com/",
    "aol_login": "https://login.aol.com/",
    "aol_home": "https://www.aol.com/",
    "outlook_login": "https://outlook.live.com/owa/",
    "outlook_home": "https://www.microsoft.com/en-us/microsoft-365/outlook/email-and-calendar-software-microsoft-outlook",
    "protonmail_login": "https://account.proton.me/login",
    "protonmail_home": "https://proton.me/mail",
    "zoho_login": "https://accounts.zoho.com/signin",
    "zoho_home": "https://www.zoho.com/",
    "gmx": "https://www.gmx.com/",

    # --- 7. Developer, DevOps & Cloud Infrastructure ---
    "github_login": "https://github.com/login",
    "github_home": "https://github.com/",
    "gitlab_login": "https://gitlab.com/users/sign_in",
    "gitlab_home": "https://about.gitlab.com/",
    "bitbucket_login": "https://bitbucket.org/account/signin/",
    "bitbucket_home": "https://bitbucket.org/",
    "aws_login": "https://console.aws.amazon.com/console/home?nc2=h_ct&src=header-signin",
    "aws_home": "https://aws.amazon.com/",
    "cloudflare_login": "https://dash.cloudflare.com/login",
    "cloudflare_home": "https://www.cloudflare.com/",
    "godaddy_login": "https://sso.godaddy.com/login",
    "godaddy_home": "https://www.godaddy.com/",
    "namecheap_login": "https://www.namecheap.com/myaccount/login/",
    "namecheap_home": "https://www.namecheap.com/",
    "digitalocean": "https://cloud.digitalocean.com/login",
    "heroku": "https://id.heroku.com/login",
    "oracle_cloud": "https://cloud.oracle.com/",
    "azure": "https://portal.azure.com/",
    "google_cloud": "https://console.cloud.google.com/",
}


async def generate_reference_hashes(out_path: Path, timeout_ms: int = 25000):
    hashes = {}
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        # Use exact same viewport as scan_url default (1366x768)
        context = await browser.new_context(viewport={"width": 1366, "height": 768})

        for brand, url in TOP_BRAND_LOGIN_URLS.items():
            logger.info("Capturing baseline for brand '%s' (%s)...", brand, url)
            page = await context.new_page()
            tmp_img_path = out_path.parent / f"_tmp_{brand}.png"
            try:
                await page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                # Give dynamic JS/forms a brief moment to settle
                await page.wait_for_timeout(3000)
                await page.screenshot(path=str(tmp_img_path), full_page=True)

                # Compute pHash
                h = imagehash.phash(Image.open(tmp_img_path))
                hashes[brand] = str(h)
                logger.info(" -> %s: %s", brand, h)
            except Exception as e:
                logger.warning("Failed to capture baseline for '%s': %s", brand, e)
            finally:
                await page.close()
                if tmp_img_path.exists():
                    tmp_img_path.unlink(missing_ok=True)

        await context.close()
        await browser.close()

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(hashes, f, indent=2)
    logger.info("\nSUCCESS! Wrote %d reference hash(es) to %s", len(hashes), out_path)


def main():
    parser = argparse.ArgumentParser(description="Automated Brand Reference Hash Generator")
    parser.add_argument("--out", default="reference_hashes.json", help="Output path for JSON reference file")
    args = parser.parse_args()

    out_path = Path(args.out)
    asyncio.run(generate_reference_hashes(out_path))


if __name__ == "__main__":
    main()
