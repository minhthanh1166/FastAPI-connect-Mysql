from fastapi import UploadFile
import firebase_admin
from firebase_admin import credentials, storage
import uuid

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred, {"storageBucket": "fastapi-67666.appspot.com"})


def generate_unique_filename(file_extension):
    return f"{uuid.uuid4()}.{file_extension}"


def upload_to_firebase_storage(file: UploadFile):
    try:
        file_extension = file.filename.split(".")[-1]
        new_filename = generate_unique_filename(file_extension)
        storage_path = f"users/{new_filename}"

        blob = storage.bucket().blob(storage_path)

        blob.upload_from_file(file.file, content_type=f"image/{file_extension}")
        blob.make_public()

        return blob.public_url
    except Exception as e:
        print(f"Error uploading image: {str(e)}")
        raise


def extract_object_path_from_url(url):
    common_prefix = "https://storage.googleapis.com/fastapi-67666.appspot.com/"
    if url.startswith(common_prefix):
        return url[len(common_prefix):]
    raise ValueError("URL does not have the expected prefix.")


def delete_to_firebase_storage(url):
    try:
        object_path = extract_object_path_from_url(url)
        blob = storage.bucket().blob(object_path)

        if blob.exists():
            blob.delete()
    except Exception as e:
        print(f"Error deleting image: {str(e)}")
        raise


def update_to_firebase_storage(file: UploadFile, url):
    try:
        file_extension = file.filename.split(".")[-1]
        new_filename = generate_unique_filename(file_extension)
        storage_path = f"users/{new_filename}"

        blob = storage.bucket().blob(storage_path)

        blob.upload_from_file(file.file, content_type=f"image/{file_extension}")
        blob.make_public()

        if blob.exists():
            delete_to_firebase_storage(url)

        return blob.public_url
    except Exception as e:
        print(f"Error uploading image: {str(e)}")
        raise
