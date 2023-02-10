# MinIO Compatible `quilt3`

A fork of `quilt3` that supports MinIO compatibility with minimal code changes to the offical version.

The following is the `git diff` detailing all the changes that have been made:
```diff
diff --git a/api/python/quilt3/data_transfer.py b/api/python/quilt3/data_transfer.py
index e8e9a29d..b703d7e6 100644
--- a/api/python/quilt3/data_transfer.py
+++ b/api/python/quilt3/data_transfer.py
@@ -172,6 +172,13 @@ class S3ClientProvider:

     def _build_client(self, get_config):
         session = self.get_boto_session()
+        endpoint_url = util.get_s3_endpoint_url()
+        if endpoint_url:
+            return session.client(
+                's3',
+                config=Config(signature_version='s3v4'),
+                endpoint_url=endpoint_url,
+            )
         return session.client('s3', config=get_config(session))

     def _build_standard_client(self):
@@ -542,8 +549,14 @@ def _copy_file_list_internal(file_list, results, message, callback, exceptions_t

     s3_client_provider = S3ClientProvider()  # Share provider across threads to reduce redundant public bucket checks

-    with tqdm(desc=message, total=total_size, unit='B', unit_scale=True, disable=DISABLE_TQDM) as progress, \
-         ThreadPoolExecutor(MAX_CONCURRENCY) as executor:
+    with tqdm(
+        desc=message,
+        total=total_size,
+        unit='B',
+        unit_scale=True,
+        disable=DISABLE_TQDM,
+        bar_format='{desc:<20}{percentage:3.0f}%|{bar}{r_bar}'
+    ) as progress, ThreadPoolExecutor(MAX_CONCURRENCY) as executor:

         def progress_callback(bytes_transferred):
             if stopped:
@@ -1037,12 +1050,19 @@ def _calculate_sha256_internal(src_list, sizes, results):
             # so it finishes its own tasks.
             del generator

-    with tqdm(desc="Hashing", total=total_size, unit='B', unit_scale=True, disable=DISABLE_TQDM) as progress, \
-         ThreadPoolExecutor() as executor, \
-         ThreadPoolExecutor(
-             MAX_CONCURRENCY,
-             thread_name_prefix='s3-executor',
-         ) as s3_executor:
+    with tqdm(
+        desc="Hashing",
+        total=total_size,
+        unit='B',
+        unit_scale=True,
+        disable=DISABLE_TQDM,
+        bar_format='{desc:<20}{percentage:3.0f}%|{bar}{r_bar}'
+    ) as progress, \
+    ThreadPoolExecutor() as executor, \
+    ThreadPoolExecutor(
+        MAX_CONCURRENCY,
+        thread_name_prefix='s3-executor',
+    ) as s3_executor:
         s3_context = types.SimpleNamespace(
             find_correct_client=with_lock(S3ClientProvider().find_correct_client),
             pending_parts_semaphore=threading.BoundedSemaphore(s3_max_pending_parts),
diff --git a/api/python/quilt3/main.py b/api/python/quilt3/main.py
index 680a11e7..4dff8528 100644
--- a/api/python/quilt3/main.py
+++ b/api/python/quilt3/main.py
@@ -8,6 +8,7 @@ import functools
 import json
 import sys
 import time
+import datetime

 import requests

@@ -21,6 +22,7 @@ from .util import (
     catalog_package_url,
     catalog_s3_url,
     get_from_config,
+    load_config,
 )


@@ -42,13 +44,32 @@ def cmd_config(catalog_url, **kwargs):
     """
     Configure quilt3 to a Quilt stack
     """
-    config_values = kwargs['set'] if kwargs['set'] else {}
+    config_values = kwargs['set'] or {}
+    s3_config_values = kwargs['set_s3'] or {}
     if catalog_url and config_values:
         raise QuiltException("Expected either an auto-config URL or key=value pairs, but got both.")

     if config_values:
         api.config(**config_values)
-    else:
+    if s3_config_values:
+        s3_config_keys = {'endpoint_url', 'access_key', 'secret_key'}
+        unrecognized_keys = set(s3_config_values).difference(s3_config_keys)
+        if unrecognized_keys:
+            raise QuiltException(
+                f'Unrecognized S3 config key(s): {list(unrecognized_keys)}. '
+                f'Known S3 config keys: {list(s3_config_keys)}'
+            )
+
+        s3_endpoint_url = s3_config_values.get('endpoint_url')
+        s3_access_key = s3_config_values.get('access_key')
+        s3_secret_key = s3_config_values.get('secret_key')
+
+        api.config(s3_endpoint_url=s3_endpoint_url)
+
+        if s3_access_key or s3_secret_key:
+            _update_credentials(s3_access_key, s3_secret_key)
+
+    if not (config_values or s3_config_values):
         if catalog_url is None:
             existing_catalog_url = get_from_config('navigator_url')
             if existing_catalog_url is not None:
@@ -58,6 +79,31 @@ def cmd_config(catalog_url, **kwargs):
         else:
             api.config(catalog_url)

+    if kwargs['show']:
+        print(json.dumps(load_config(), indent=4))
+
+
+def _update_credentials(access_key: str, secret_key: str):
+    old_creds = session._load_credentials()
+    access_key = access_key or old_creds.get('access_key')
+    secret_key = secret_key or old_creds.get('secret_key')
+    new_creds = _make_credentials(access_key, secret_key)
+    session._save_credentials(new_creds)
+
+
+def _make_credentials(access_key: str, secret_key: str):
+    # TODO: currently hardcoding expiry time a year out and token always None...?
+    expiry_time = (
+        datetime.datetime.utcnow().astimezone() + datetime.timedelta(days=365)
+    ).isoformat()
+    token = None
+    return dict(
+        access_key=access_key,
+        secret_key=secret_key,
+        token=token,
+        expiry_time=expiry_time
+    )
+

 class ParseConfigDict(argparse.Action):
     def __call__(self, parser, namespace, values, option_string=None):
@@ -247,16 +293,34 @@ def create_parser():
         nargs="?"
     )
     config_p.add_argument(
-            "--set",
-            metavar="KEY=VALUE",
-            nargs="+",
-            help="Set a number of key-value pairs for config_values"
-                 "(do not put spaces before or after the = sign). "
-                 "If a value contains spaces, you should define "
-                 "it with double quotes: "
-                 'foo="this is a sentence". Note that '
-                 "values are always treated as strings.",
-            action=ParseConfigDict,
+        "--set",
+        metavar="KEY=VALUE",
+        nargs="+",
+        help="Set a number of key-value pairs for config_values "
+            "(do not put spaces before or after the = sign). "
+            "If a value contains spaces, you should define "
+            "it with double quotes: "
+            'foo="this is a sentence". Note that '
+            "values are always treated as strings.",
+        action=ParseConfigDict,
+    )
+    config_p.add_argument(
+        "--set-s3",
+        metavar="KEY=VALUE",
+        nargs="+",
+        help="Set a number of key-value pairs for S3-related config values "
+            "(do not put spaces before or after the = sign). "
+            "If a value contains spaces, you should define "
+            "it with double quotes: "
+            'foo="this is a sentence". Note that '
+            "values are always treated as strings.",
+        action=ParseConfigDict,
+    )
+    config_p.add_argument(
+        "--show",
+        default=False,
+        action="store_true",
+        help="Print the Quilt configuration"
     )
     config_p.set_defaults(func=cmd_config)

diff --git a/api/python/quilt3/packages.py b/api/python/quilt3/packages.py
index 882b13cc..83bd80b5 100644
--- a/api/python/quilt3/packages.py
+++ b/api/python/quilt3/packages.py
@@ -576,12 +576,24 @@ class Package:
         validate_package_name(name)
         registry = get_package_registry(registry)

-        top_hash = (
-            get_bytes(registry.pointer_latest_pk(name)).decode()
-            if top_hash is None else
-            registry.resolve_top_hash(name, top_hash)
-        )
-        pkg_manifest = registry.manifest_pk(name, top_hash)
+        # NOTE: mdlk - added try/except here to make s3 request errors more specific
+        #       for upstream handling
+        try:
+            top_hash = (
+                get_bytes(registry.pointer_latest_pk(name)).decode()
+                if top_hash is None else
+                registry.resolve_top_hash(name, top_hash)
+            )
+            pkg_manifest = registry.manifest_pk(name, top_hash)
+        except botocore.exceptions.ClientError as e:
+            if e.response["Error"]["Code"] == "NoSuchBucket":
+                raise QuiltException(
+                    f"Unable to locate registry '{registry.base}'")
+            elif e.response["Error"]["Code"] == "NoSuchKey":
+                raise QuiltException(
+                    f"Unable to locate package '{name}' in registry '{registry.base}'")
+            else:
+                raise

         def download_manifest(dst):
             copy_file(pkg_manifest, PhysicalKey.from_path(dst), message="Downloading manifest")
@@ -774,7 +786,7 @@ class Package:
                     unit="",
                     unit_scale=True,
                     disable=DISABLE_TQDM,
-                    bar_format='{l_bar}{bar}| {n}/{total} [{elapsed}<{remaining}, {rate_fmt}]',
+                    bar_format='{desc:<20}{percentage:3.0f}%|{bar}{r_bar}'
                 ),
                 loads=ManifestJSONDecoder().decode,
             )
@@ -860,6 +872,14 @@ class Package:
             for f in files:
                 if not f.is_file():
                     continue
+
+                # filter out metafile
+                # TODO: mdlk - this is the most convenient place to add this for the sake of
+                #       mstc-quilt downstream, but does not belong in core quilt3... how to
+                #       handle this in mstc-quilt?
+                if f.name == '.quilt-package':
+                    continue
+
                 logical_key = f.relative_to(src_path).as_posix()
                 # check update policy
                 if update_policy == 'existing' and logical_key in root:
diff --git a/api/python/quilt3/util.py b/api/python/quilt3/util.py
index 5c922d03..e8c02c12 100644
--- a/api/python/quilt3/util.py
+++ b/api/python/quilt3/util.py
@@ -443,6 +443,7 @@ def load_config():
     return local_config


+
 def get_from_config(key):
     return load_config().get(key)

@@ -559,3 +560,11 @@ def catalog_package_url(catalog_url, bucket, package_name, package_timestamp="la
     if tree:
         package_url = package_url + f"/tree/{package_timestamp}"
     return package_url
+
+
+def get_s3_endpoint_url():
+    try:
+        return os.environ["QUILT_S3_ENDPOINT_URL"]
+    except KeyError:
+        pass
+    return get_from_config("s3_endpoint_url")
diff --git a/api/python/quilt3/workflows/__init__.py b/api/python/quilt3/workflows/__init__.py
index a27f30c5..3fafedac 100644
--- a/api/python/quilt3/workflows/__init__.py
+++ b/api/python/quilt3/workflows/__init__.py
@@ -146,7 +146,7 @@ class WorkflowConfig:

         return schema_pk

-    def load_schema(self, schema_pk: util.PhysicalKey) -> (bytes, util.PhysicalKey):
+    def load_schema(self, schema_pk: util.PhysicalKey) -> typing.Tuple[bytes, util.PhysicalKey]:
         handled_exception = (OSError if schema_pk.is_local() else botocore.exceptions.ClientError)
         try:
             return get_bytes_and_effective_pk(schema_pk)

```
