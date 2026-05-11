import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { createCipheriv, createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';

const repoDir = process.cwd();
const sourceDir = process.env.BLOG_SOURCE_DIR;
const password = process.env.BLOG_PROTECT_PASSWORD;

if (!sourceDir) {
  throw new Error('BLOG_SOURCE_DIR is required.');
}

if (!password) {
  throw new Error('BLOG_PROTECT_PASSWORD is required.');
}

const config = JSON.parse(await readFile(path.join(repoDir, 'protect.config.json'), 'utf8'));
const tempDir = await mkdtemp(path.join(os.tmpdir(), 'blog-protect-'));

const SITE_SALT = randomBytes(16).toString('base64');
const PASSWORD_HASH = sha256Base64(`${password}::${SITE_SALT}`);
const PBKDF2_ITERATIONS = 250000;

const listPatterns = [
  /^index\.html$/,
  /^page\/\d+\/index\.html$/,
  /^archives(?:\/.*)?\/index\.html$/,
  /^categories(?:\/.*)?\/index\.html$/,
  /^tags(?:\/.*)?\/index\.html$/
];

const postPattern = /^\d{4}\/\d{2}\/\d{2}\/.+\/index\.html$/;
await cp(sourceDir, tempDir, {
  recursive: true,
  filter: (src) => !src.endsWith('.DS_Store')
});

await copyFileIfExists(path.join(repoDir, 'protect.config.json'), path.join(tempDir, 'protect.config.json'));
await copyFileIfExists(path.join(repoDir, 'js/protect-runtime.js'), path.join(tempDir, 'js/protect-runtime.js'));
await copyFileIfExists(path.join(repoDir, 'js/local-search.js'), path.join(tempDir, 'js/local-search.js'));
await copyFileIfExists(path.join(repoDir, 'tools/protect-site.mjs'), path.join(tempDir, 'tools/protect-site.mjs'));

const files = await collectFiles(tempDir);
const relFiles = files.map((file) => path.relative(tempDir, file).split(path.sep).join('/'));

const protectedPages = new Set(
  relFiles.filter((relPath) => postPattern.test(relPath) || config.protectedStandalonePages.includes(relPath))
);

const publicPages = new Set(config.publicWhitelist);

await writeFile(
  path.join(tempDir, 'robots.txt'),
  [
    'User-agent: *',
    'Disallow: /',
    `Allow: ${config.robotsAllow[0]}`,
    `Allow: ${config.robotsAllow[1]}`,
    `Allow: ${config.robotsAllow[2]}`
  ].join('\n') + '\n',
  'utf8'
);

for (const relPath of relFiles) {
  if (!relPath.endsWith('.html')) {
    continue;
  }

  const absPath = path.join(tempDir, relPath);
  let html = await readFile(absPath, 'utf8');

  if (protectedPages.has(relPath)) {
    html = await protectSinglePage(tempDir, relPath, html);
  } else if (matchesListPage(relPath)) {
    html = protectListPage(relPath, html);
  } else if (publicPages.has(relPath)) {
    html = allowPublicPage(html);
  } else {
    html = protectListPage(relPath, html);
  }

  await writeFile(absPath, html, 'utf8');
}

await rewriteContentJson(path.join(tempDir, 'content.json'), protectedPages);
await rewriteLocalSearch(path.join(tempDir, 'local-search.xml'), protectedPages);
await rewriteLocalSearch(path.join(tempDir, 'xml/local-search.xml'), protectedPages);
await patchSearchRuntime(path.join(tempDir, 'js/local-search.js'));

await rmContents(repoDir);
await copyBack(tempDir, repoDir);

console.log(`Protected site generated from ${sourceDir}`);

async function protectSinglePage(rootDir, relPath, html) {
  const absPath = path.join(rootDir, relPath);
  const pageDir = path.dirname(absPath);

  const title = extractMatch(html, /<h1 style="display: none">([^<]*)<\/h1>/) ||
    extractMetaTitle(html) ||
    '';
  const contentBlock = extractMatch(
    html,
    /<div class="markdown-body">([\s\S]*?)<\/div>\s*(?:<hr>|<\/article>)/
  ) ||
    '';

  const { html: sanitizedHtml, assets } = rewriteProtectedAssetReferences(relPath, contentBlock);
  const encryptedPayload = encryptJson({
    title,
    html: sanitizedHtml,
    assets
  });

  const payloadName = '__protected.json';
  await writeFile(path.join(pageDir, payloadName), JSON.stringify(encryptedPayload), 'utf8');

  await moveLocalAssets(pageDir);

  const hiddenCommentClass = html.includes('<article class="comments"') ? ' data-protect-hide="true"' : '';
  const pageGate = `
<section class="protect-panel" data-protect-gate>
  <h2 class="protect-title">Protected content</h2>
  <p class="protect-copy">This page requires the site password.</p>
  <form class="protect-form" data-protect-form>
    <input class="protect-input" type="password" autocomplete="current-password" data-protect-input placeholder="Enter password">
    <button class="protect-button" type="submit">Unlock</button>
  </form>
  <p class="protect-status" data-protect-status></p>
</section>
<div class="markdown-body" data-protect-content-target></div>
`;

  html = replaceMetaDescriptions(html, config.seoProtectedDescription);
  html = ensureNoindex(html);
  html = injectStyle(html);
  html = injectRuntimeScript(html);
  html = injectJsonScript(
    html,
    'data-protect-page-options',
    {
      payloadPath: relativeUrl(relPath, payloadName),
      siteSalt: SITE_SALT,
      passwordHash: PASSWORD_HASH
    }
  );

  if (html.includes('<article class="post-content mx-auto">')) {
    html = html.replace(
      /<article class="post-content mx-auto">[\s\S]*?<article class="comments"[\s\S]*?<\/article>\s*<\/article>/,
      `<article class="post-content mx-auto">
            <!-- SEO header -->
            <h1 style="display: none">${escapeHtml(title)}</h1>
            ${pageGate}
            <article class="comments d-none" data-protect-comments="true"></article>
          </article>`
    );
  } else {
    html = html.replace(
      /<article class="page-content">[\s\S]*?<article class="comments"[\s\S]*?<\/article>\s*<\/article>/,
      `<article class="page-content">
  ${pageGate}
  <article class="comments d-none" data-protect-comments="true"></article>
</article>`
    );
  }

  return html;
}

function protectListPage(relPath, html) {
  html = html.replace(/<p class="index-excerpt">[\s\S]*?<\/p>/g, '');
  html = html.replace(/<meta name="description" content="[^"]*">/g, `<meta name="description" content="${escapeAttr(config.seoProtectedDescription)}">`);
  html = html.replace(/<meta property="og:description" content="[^"]*">/g, `<meta property="og:description" content="${escapeAttr(config.seoProtectedDescription)}">`);
  html = ensureNoindex(html);
  html = injectStyle(html);
  html = injectRuntimeScript(html);
  html = injectJsonScript(html, 'data-protect-site-options', {
    siteSalt: SITE_SALT,
    passwordHash: PASSWORD_HASH
  });

  const gate = `
<section class="protect-panel protect-site-panel" data-site-protect-gate>
  <h2 class="protect-title">Protected blog</h2>
  <p class="protect-copy">Unlock to read post content.</p>
  <form class="protect-form" data-site-protect-form>
    <input class="protect-input" type="password" autocomplete="current-password" data-site-protect-input placeholder="Enter password">
    <button class="protect-button" type="submit">Unlock</button>
  </form>
  <p class="protect-status" data-site-protect-status></p>
</section>
`;

  if (html.includes('<div class="container">')) {
    html = html.replace('<div class="container">', `<div class="container">\n${gate}`);
  }

  return html;
}

function allowPublicPage(html) {
  return removeNoindex(html);
}

async function rewriteContentJson(absPath, protectedSet) {
  const json = JSON.parse(await readFile(absPath, 'utf8'));
  json.meta.protected = true;

  json.pages = json.pages.map((page) => {
    const normalized = normalizePagePath(page.path || '');
    if (!protectedSet.has(normalized)) {
      return page;
    }

    return {
      ...page,
      excerpt: '',
      text: '',
      protected: true
    };
  });

  json.posts = json.posts.map((post) => {
    const normalized = normalizePagePath(post.path || '');
    if (!protectedSet.has(normalized)) {
      return post;
    }

    return {
      ...post,
      excerpt: '',
      text: '',
      protected: true
    };
  });

  await writeFile(absPath, JSON.stringify(json), 'utf8');
}

async function rewriteLocalSearch(absPath, protectedSet) {
  let xml = await readFile(absPath, 'utf8');
  xml = xml.replace(/<entry>[\s\S]*?<\/entry>/g, (entry) => {
    const url = extractMatch(entry, /<url>([^<]+)<\/url>/) || '';
    const normalized = normalizePagePath(url);
    if (!protectedSet.has(normalized)) {
      return entry;
    }
    return entry.replace(/<content type="html"><!\[CDATA\[[\s\S]*?\]\]><\/content>/, '<content type="html"><![CDATA[]]></content>');
  });
  await writeFile(absPath, xml, 'utf8');
}

async function patchSearchRuntime(absPath) {
  let js = await readFile(absPath, 'utf8');
  js = js.replace(
    "            // only match articles with not empty contents\n            if (data_content !== '') {\n",
    "            // allow title-only results for protected posts\n            if (data_content !== '' || data_title !== '') {\n"
  );
  js = js.replace(
    "              var content = orig_data_content;\n              if (first_occur >= 0) {\n",
    "              var content = orig_data_content;\n              if (content && first_occur >= 0) {\n"
  );
  await writeFile(absPath, js, 'utf8');
}

async function moveLocalAssets(pageDir) {
  const files = await readdir(pageDir);
  const assetDir = path.join(pageDir, '__protected-assets');
  await rm(assetDir, { recursive: true, force: true });
  await mkdir(assetDir, { recursive: true });
  for (const file of files) {
    if (file === 'index.html' || file === '__protected.json' || file === '__protected-assets') {
      continue;
    }
    await cp(path.join(pageDir, file), path.join(assetDir, file), { recursive: true });
  }
  for (const file of files) {
    if (file === 'index.html' || file === '__protected.json' || file === '__protected-assets') {
      continue;
    }
    await rm(path.join(pageDir, file), { recursive: true, force: true });
  }
}

function encryptJson(payload) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    iterations: PBKDF2_ITERATIONS,
    ciphertext: Buffer.concat([ciphertext, tag]).toString('base64')
  };
}

function extractMetaTitle(html) {
  return extractMatch(html, /<meta property="og:title" content="([^"]*)">/);
}

function extractMatch(text, regex) {
  const match = text.match(regex);
  return match ? match[1] : '';
}

function injectStyle(html) {
  if (html.includes('protect-panel')) {
    return html;
  }

  const style = `
<style>
  .protect-panel { max-width: 560px; margin: 2rem auto; padding: 2rem; border: 1px solid rgba(47,65,84,0.18); border-radius: 8px; background: #fff; }
  .protect-title { margin-bottom: 0.75rem; font-size: 1.5rem; }
  .protect-copy { margin-bottom: 1rem; color: #5c6773; }
  .protect-form { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  .protect-input { flex: 1 1 260px; min-height: 44px; padding: 0.75rem 0.9rem; border: 1px solid rgba(47,65,84,0.25); border-radius: 6px; }
  .protect-button { min-height: 44px; padding: 0.75rem 1.1rem; border: none; border-radius: 6px; background: #2f4154; color: #fff; }
  .protect-status { margin-top: 0.75rem; min-height: 1.2rem; color: #5c6773; }
  .protect-error { color: #b42318; }
  .protect-site-gated .index-excerpt { display: none !important; }
  [data-protect-hide] { display: none !important; }
</style>`;

  return html.replace('</head>', `${style}\n</head>`);
}

function injectRuntimeScript(html) {
  if (html.includes('/js/protect-runtime.js')) {
    return html;
  }
  return html.replace('</body>', '<script src="/js/protect-runtime.js"></script>\n</body>');
}

function injectJsonScript(html, attribute, payload) {
  const tag = `<script type="application/json" ${attribute}>${JSON.stringify(payload)}</script>`;
  return html.replace('</body>', `${tag}\n</body>`);
}

function ensureNoindex(html) {
  if (html.includes('name="robots"')) {
    return html.replace(/<meta name="robots" content="[^"]*">/, '<meta name="robots" content="noindex,nofollow,noarchive">');
  }
  return html.replace('</head>', '<meta name="robots" content="noindex,nofollow,noarchive">\n</head>');
}

function removeNoindex(html) {
  return html.replace(/<meta name="robots" content="noindex,nofollow,noarchive">\n?/g, '');
}

function replaceMetaDescriptions(html, text) {
  html = html.replace(/<meta name="description" content="[^"]*">/g, `<meta name="description" content="${escapeAttr(text)}">`);
  html = html.replace(/<meta property="og:description" content="[^"]*">/g, `<meta property="og:description" content="${escapeAttr(text)}">`);
  return html;
}

function rewriteProtectedAssetReferences(relPath, html) {
  const relDir = path.dirname(relPath).split(path.sep).join('/');
  const assets = {};
  let index = 0;

  const rewritten = html.replace(
    /<(img|source|a)([^>]*?)\s(?:src|href)="([^"]+)"([^>]*)>/g,
    (match, tag, before, rawUrl, after) => {
      if (!isLocalAsset(relDir, rawUrl)) {
        return match;
      }

      const cleanUrl = stripLeadingSlash(rawUrl).replace(/%20/g, ' ');
      const fileName = path.basename(cleanUrl);
      const key = `asset-${index}`;
      index += 1;
      assets[key] = `./__protected-assets/${encodeURIComponent(fileName)}`;

      const attrName = tag === 'a' ? 'href' : 'src';
      return `<${tag}${before} ${attrName}="" data-protect-asset="${key}"${after}>`;
    }
  );

  return { html: rewritten, assets };
}

function isLocalAsset(relDir, rawUrl) {
  if (!rawUrl) {
    return false;
  }
  if (/^(https?:)?\/\//i.test(rawUrl) || rawUrl.startsWith('mailto:') || rawUrl.startsWith('#')) {
    return false;
  }
  const normalized = stripLeadingSlash(rawUrl);
  return normalized.startsWith(`${relDir}/`);
}

function stripLeadingSlash(value) {
  return value.replace(/^\//, '');
}

function matchesListPage(relPath) {
  return listPatterns.some((pattern) => pattern.test(relPath));
}

function normalizePagePath(urlOrPath) {
  const clean = decodeURIComponent(urlOrPath.replace(/^\//, '').replace(/\/$/, ''));
  if (clean.endsWith('index.html')) {
    return clean;
  }
  return `${clean}/index.html`;
}

async function collectFiles(root) {
  const result = [];
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.pop();
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      if (entry.name === '.git') {
        continue;
      }
      if (entry.isDirectory()) {
        queue.push(abs);
      } else {
        result.push(abs);
      }
    }
  }
  return result;
}

async function rmContents(dir) {
  const entries = await readdir(dir);
  for (const entry of entries) {
    if (entry === '.git') {
      continue;
    }
    await rm(path.join(dir, entry), { recursive: true, force: true });
  }
}

async function copyBack(fromDir, toDir) {
  const entries = await readdir(fromDir);
  for (const entry of entries) {
    await cp(path.join(fromDir, entry), path.join(toDir, entry), { recursive: true });
  }
}

async function copyFileIfExists(from, to) {
  try {
    await cp(from, to, { recursive: true });
  } catch (error) {
    if (error && error.code !== 'ENOENT') {
      throw error;
    }
  }
}

function relativeUrl(relPagePath, fileName) {
  return `./${fileName}`;
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function escapeAttr(text) {
  return escapeHtml(text).replace(/"/g, '&quot;');
}

function sha256Base64(value) {
  return createHash('sha256').update(value).digest('base64');
}
