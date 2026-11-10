import json
import os
import uuid
from io import BytesIO

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from PIL import Image
from rest_framework.exceptions import ValidationError

# the damaged 1x1 "logo" found on a server (bad checksums, cut off): browsers show a broken image
DAMAGED_PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f1563340000000d49444154789c636000000002000148afa4'
    '710000000049454e44ae426082')


def png(width, height):
    buffer = BytesIO()
    Image.new('RGBA', (width, height), (56, 189, 248, 255)).save(buffer, 'PNG')
    return buffer.getvalue()


class InterfaceLogoTest(TestCase):
    """ A logo is a complete image a browser can draw: a damaged one is refused, and one already stored falls back to
    the default logo instead of a broken image. """

    def test_only_complete_images_of_a_usable_size_are_readable(self):
        from xpack.api.interface import readable_image
        self.assertTrue(readable_image(png(185, 55)))
        self.assertFalse(readable_image(DAMAGED_PNG))
        self.assertFalse(readable_image(png(1, 1)))
        self.assertFalse(readable_image(png(185, 55)[:-40]))   # (cut off)

    def test_a_damaged_upload_is_refused(self):
        from xpack.api.interface import validate_uploaded_image
        with self.assertRaises(ValidationError):
            validate_uploaded_image(SimpleUploadedFile('logo.png', DAMAGED_PNG, 'image/png'), 'logo_index')
        name = validate_uploaded_image(SimpleUploadedFile('logo.png', png(185, 55), 'image/png'), 'logo_index')
        self.assertTrue(name.startswith('custom_logo_index_') and name.endswith('.png'))

    def test_a_damaged_stored_logo_shows_the_default(self):
        from xpam.context_processor import default_interface
        from settings.models import Setting
        from settings.utils.common import get_interface_setting_or_default
        from xpack.api.interface import INTERFACE_UPLOAD_DIR, INTERFACE_UPLOAD_URL
        os.makedirs(INTERFACE_UPLOAD_DIR, exist_ok=True)
        names = {}
        for kind, content in (('damaged', DAMAGED_PNG), ('good', png(185, 55))):
            names[kind] = f'test_{kind}_{uuid.uuid4().hex[:8]}.png'
            path = os.path.join(INTERFACE_UPLOAD_DIR, names[kind])
            with open(path, 'wb') as f:
                f.write(content)
            self.addCleanup(os.remove, path)
        Setting.objects.update_or_create(name='INTERFACE', defaults={'value': json.dumps({
            'logo_index': INTERFACE_UPLOAD_URL + names['damaged'],
            'logo_logout': INTERFACE_UPLOAD_URL + names['good'],
        })})
        data = get_interface_setting_or_default()
        self.assertEqual(data['logo_index'], default_interface['logo_index'])
        self.assertEqual(data['logo_logout'], INTERFACE_UPLOAD_URL + names['good'])
