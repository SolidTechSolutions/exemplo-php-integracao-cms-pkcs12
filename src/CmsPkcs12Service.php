<?php
declare(strict_types=1);

/**
 * [EN]    CAdES (CMS) signing — PKCS#12 pre-imported certificate (one-step).
 *         CMS signatures have no visual fields. Use signaturePackaging to choose
 *         ENVELOPING, ENVELOPED, or DETACHED.
 * [PT-BR] Assinatura CAdES (CMS) — certificado PKCS#12 pré-importado (passo único).
 *         Assinaturas CMS não possuem campos visuais. Use signaturePackaging para escolher
 *         ENVELOPING, ENVELOPED ou DETACHED.
 */

namespace SolidSign;

use GuzzleHttp\Client;
use ZipArchive;

class CmsPkcs12Service
{
    private Client $client;

    public function __construct()
    {
        $this->client = new Client(['http_errors' => false]);
    }

    // ── Batch (local files) ───────────────────────────────────────────────────

    public function signBatch(string $inputPath, string $outputPath): ?string
    {
        $files = array_merge(
            glob(rtrim($inputPath, '/') . '/*.*') ?: []
        );
        if (empty($files)) {
            error_log("No files found in $inputPath");
            return null;
        }

        $multipart = [];
        foreach ($files as $i => $path) {
            $multipart[] = ['name' => "document[$i]", 'contents' => fopen($path, 'r'), 'filename' => basename($path)];
        }

        $multipart[] = ['name' => 'pfxCode',            'contents' => $_ENV['SOLIDSIGN_CERT_ID'] ?? ''];
        $multipart[] = ['name' => 'profile',            'contents' => $_ENV['SOLIDSIGN_PROFILE'] ?? 'ADRB'];
        $multipart[] = ['name' => 'hashAlgorithm',      'contents' => $_ENV['SOLIDSIGN_HASH_ALGORITHM'] ?? 'SHA256'];
        $multipart[] = ['name' => 'signaturePackaging', 'contents' => $_ENV['SOLIDSIGN_SIGNATURE_PACKAGING'] ?? 'ENVELOPING'];
        if (!empty($_ENV['SOLIDSIGN_POLICY_VERSION'])) {
            $multipart[] = ['name' => 'policyVersion', 'contents' => $_ENV['SOLIDSIGN_POLICY_VERSION']];
        }

        $baseUrl = rtrim($_ENV['SOLIDSIGN_BASE_URL'] ?? 'http://localhost:8080', '/');
        $auth    = $_ENV['SOLIDSIGN_AUTHORIZATION'] ?? '';

        $response = $this->client->post("$baseUrl/solidsign/dsig/cms/sign-pkcs12", [
            'headers'   => ['Authorization' => $auth],
            'multipart' => $multipart,
        ]);

        if ($response->getStatusCode() >= 400) {
            error_log("SolidSign error {$response->getStatusCode()}: " . $response->getBody());
            return null;
        }

        $signResp  = json_decode((string) $response->getBody(), true);
        $origNames = array_map('basename', $files);
        return $this->downloadAndZip($signResp, $origNames, $auth, $outputPath, 'signed_cms_pkcs12');
    }

    // ── Form (uploaded files) ─────────────────────────────────────────────────

    public function signForm(array $params, array $files): ?string
    {
        $multipart = [];
        foreach ($files['document'] ?? [] as $i => $f) {
            $multipart[] = ['name' => "document[$i]", 'contents' => $f['content'], 'filename' => $f['filename']];
        }

        $textFields = ['pfxCode', 'profile', 'hashAlgorithm', 'policyVersion',
                       'signaturePackaging', 'encapsulatedTimestampConfig', 'documentInfoMetadata'];
        foreach ($textFields as $field) {
            if (isset($params[$field]) && $params[$field] !== '') {
                $multipart[] = ['name' => $field, 'contents' => $params[$field]];
            }
        }

        $baseUrl = rtrim($params['baseUrl'] ?? '', '/');
        $auth    = $params['authorization'] ?? '';

        $response = $this->client->post("$baseUrl/solidsign/dsig/cms/sign-pkcs12", [
            'headers'   => ['Authorization' => $auth],
            'multipart' => $multipart,
        ]);

        if ($response->getStatusCode() >= 400) {
            error_log("SolidSign error {$response->getStatusCode()}: " . $response->getBody());
            return null;
        }

        $signResp  = json_decode((string) $response->getBody(), true);
        $origNames = array_column($files['document'] ?? [], 'filename');
        $tmpDir    = sys_get_temp_dir() . '/solidsign_out_' . uniqid();
        return $this->downloadAndZip($signResp, $origNames, $auth, $tmpDir, 'signed_cms');
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function downloadAndZip(array $signResp, array $origNames, string $auth, string $outputDir, string $prefix): ?string
    {
        if (!is_dir($outputDir)) {
            mkdir($outputDir, 0777, true);
        }
        $tmpDir = sys_get_temp_dir() . '/solidsign_dl_' . uniqid();
        mkdir($tmpDir, 0777, true);

        foreach ($signResp['documents'] ?? [] as $i => $doc) {
            $selfHref = $doc['_links']['self']['href'] ?? null;
            if ($selfHref === null) {
                foreach ($doc['links'] ?? [] as $link) {
                    if ($link['rel'] === 'self') { $selfHref = $link['href']; break; }
                }
            }
            if ($selfHref === null) continue;

            $dlResp = $this->client->get($selfHref, ['headers' => ['Authorization' => $auth]]);
            if ($dlResp->getStatusCode() >= 400) continue;
            $origName = $origNames[$i] ?? "document_$i";
            file_put_contents("$tmpDir/signed_$origName", (string) $dlResp->getBody());
        }

        $zipPath = "$outputDir/{$prefix}_" . time() . '.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        foreach (glob("$tmpDir/*") ?: [] as $file) {
            $zip->addFile($file, basename($file));
        }
        $zip->close();

        foreach (glob("$tmpDir/*") ?: [] as $file) { unlink($file); }
        rmdir($tmpDir);

        echo "CAdES PKCS12 signing complete. Output: $zipPath\n";
        return $zipPath;
    }
}
