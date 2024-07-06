go run setup.go --sk temps/sk.bin --cc temps/cc.bin --input temps/in.bin --key_public temps/pub.bin --key_eval temps/mult.bin

go run main.go --cc temps/cc.bin --input temps/in.bin --output temps/out.bin --key_public temps/pub.bin --key_eval temps/mult.bin

go run verify.go --sk temps/sk.bin --cc temps/cc.bin --input temps/in.bin --output temps/out.bin