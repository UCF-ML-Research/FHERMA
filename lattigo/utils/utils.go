package utils

import (
	"encoding"
	"fmt"
	"image"
	_ "image/jpeg" // 如果图像是JPEG格式，导入JPEG解码器
	_ "image/png"  // 如果图像是PNG格式，导入PNG解码器
	"io"
	"os"
)

func Serialize(object interface{}, path string) (err error) {

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("os.Create(%s): %w", path, err)
	}

	defer f.Close()

	switch object := object.(type) {
	case io.WriterTo:
		if _, err = object.WriteTo(f); err != nil {
			return fmt.Errorf("%T.WriteTo: %w", object, err)
		}
	case encoding.BinaryMarshaler:
		var data []byte
		if data, err = object.MarshalBinary(); err != nil {
			return fmt.Errorf("%T.MarshalBinary: %w", object, err)
		}
		if _, err = f.Write(data); err != nil {
			return fmt.Errorf("file.Write: %w", err)
		}
	default:
		return fmt.Errorf("%T does not implement io.WriterTo or encoding.BinaryMarshaler")
	}

	return
}

func Deserialize(object interface{}, path string) (err error) {

	switch object := object.(type) {
	case io.ReaderFrom:
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("os.Open(%s): %w", path, err)
		}
		defer f.Close()

		if _, err = object.ReadFrom(f); err != nil {
			return fmt.Errorf("%T.ReadFrom: %w", object, err)
		}
	case encoding.BinaryUnmarshaler:
		var data []byte
		if data, err = os.ReadFile(path); err != nil {
			return fmt.Errorf("os.ReadFile(%s): %w", path, err)
		}

		if err = object.UnmarshalBinary(data); err != nil {
			return fmt.Errorf("%T.UnmarshalBinary: %w", object, err)
		}

	default:
		return fmt.Errorf("%T does not implement io.ReaderFrom or encoding.BinaryUnmarshaler")
	}

	return
}

func LoadImageToVector(filePath string, slots int) ([]float64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("error decoding image: %v", err)
	}

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	if width != 32 || height != 32 {
		return nil, fmt.Errorf("image must be 32x32 pixels")
	}

	vector := make([]float64, slots)

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(x, y).RGBA()

			r = r >> 8
			g = g >> 8
			b = b >> 8

			index := y*width + x
			vector[index] = float64(r)
			vector[1024+index] = float64(g)
			vector[2048+index] = float64(b)
		}
	}

	return vector, nil
}
