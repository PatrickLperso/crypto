#!/usr/bin/env python3

import os, sys
import numpy as np
from PIL import Image

if __name__ == "__main__":

    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ressources")

    flag_frame = Image.open(os.path.join(folder, 'flag.png'))
    flag_np = np.array(flag_frame.getdata()).reshape((flag_frame.height, flag_frame.width, 3))

    lemur_frame = Image.open(os.path.join(folder, 'lemur.png'))
    lemur_np = np.array(lemur_frame.getdata()).reshape((lemur_frame.height, lemur_frame.width, 3))

    new_image_np = np.array([x[0] ^ x[1] for x in zip(lemur_np.flatten(), flag_np.flatten())]).reshape((flag_frame.height, flag_frame.width, 3)).astype(np.uint8)

    new_image = Image.fromarray(new_image_np)
    new_image.save(os.path.join(folder, 'new_image.png'))

