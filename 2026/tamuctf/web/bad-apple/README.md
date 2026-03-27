# bad-apple

## 1. Summary

- **Category**: Web
- **Points**: 50
- **Solves**: 463

### Description

> `funny touhou reference`

## 2. Analysis

### Vulnerability

- **Directory Indexing & Insecure File Access**: The server configuration allows directory listing via `Options +Indexes`. While direct access to `.gif` files is restricted by Basic Authentication, the application logic in the `/convert` and `index` routes allows an attacker to process and view files if the filename is known.

## 3. Exploit Flow

1. **Information Gathering (Directory Indexing)**
   The `httpd-append.conf` file contains the following configuration:

   ```apache
   Alias /browse /srv/http/uploads
   <Directory /srv/http/uploads>
       Options +Indexes
       <FilesMatch "\.gif$">
           AuthType Basic
           AuthName "Admin Area"
           AuthUserFile /srv/http/.htpasswd
           Require valid-user
       </FilesMatch>
   </Directory>
   ```

   By accessing the `/browse` alias, we can view the file list due to directory indexing. Inside the `/admin` directory, a randomized flag filename was discovered: `e017b6321bda6812ec80e9fac368709e-flag.gif`. However, direct download was blocked by the `Require valid-user` directive.

2. **Bypassing Authentication via Frame Extraction**
   The application provides a `/convert` endpoint that extracts frames from a GIF:

   ```python
   @app.route('/convert')
   def convert():
       user_id = request.args.get('user_id', 'anonymous')
       filename = request.args.get('filename', '')

       input_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(user_id), filename)
       # ... logic to extract frames ...
   ```

   Since we already know the target filename, we can trigger the extraction process. Once extracted, the `index` route allows us to view the resulting `.png` frames without undergoing the `.gif` authentication check:

   ```python
   view_gif = request.args.get('view')
   view_user_id = request.args.get('view_user_id', user_id)
   if view_gif:
       view_frames_dir = os.path.join(FRAMES_BASE, view_user_id, view_gif)
       # ... logic to list and display png frames ...
   ```

3. **Execution**
   By navigating to the following URL, we can bypass the restriction and view the flag frames:
   `/?view=e017b6321bda6812ec80e9fac368709e-flag&view_user_id=admin`

## 4. Flag

`gigem{3z_t0h0u_fl4g_r1t3}`
