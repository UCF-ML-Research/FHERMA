# FHERMA

This repository contains the code for the Fully Homomorphic Encryption (FHE) competition, i.e., [CIFAR Challenge](https://fherma.io/challenges/652bf663485c878710fd0209/overview), organized by [Fair Math](https://fairmath.xyz/) and [OpenFHE](https://www.openfhe.org/).

The goal of the challenge is to develop and implement a machine learning model capable of efficiently classifying encrypted CIFAR-10 images without decrypting them.

The code is organized and maintained by the member Jiaqi Xue of Dr.Qian Lou's Lab at the University of Central Florida (UCF).

## Competition Achievements
The competition featured two tracks, OpenFHE and Lattigo, each with two awards: one for top accuracy and another for top efficiency with accuracy over 85%. Our team achieved high rankings in both tracks. For more details, visit the official website: [CIFAR Challenge Rankings](https://fherma.io/challenges/652bf663485c878710fd0209/leaderboard).

- **OpenFHE Accuracy Award**: Tied-First Place
- **Lattigo Accuracy Award**: Tied-First Place
- **OpenFHE Efficiency Award**: Second Place
- **Lattigo Efficiency Award**: Third Place

## Installation
```bash
git clone https://github.com/UCF-lab/FHE-CIFAR10.git
cd FHERMA
```

- Install OpenFHE following the instructions in the [OpenFHE repository](https://github.com/openfheorg/openfhe-development)

- Install Lattigo following the instructions in the [Lattigo repository](https://github.com/tuneinsight/lattigo)


## OpenFHE
### Quick Start
```bash
cd openfhe

mkdir keys temp data

mkdir build & cd build

cmake ..
make
./app --key_pub ../keys/public-key.txt --key_mult ../keys/mult-key.txt --key_rot ../keys/rot-key.txt --input ../inputs/input.txt --output ../inputs/output.txt --mode gen --cc crypto-context.txt
```

### Explanation
The code is organized as follows:
- `openfhe/weights/` contains the weights of the model:
  - conv3x8-full-90: model with one convolutional layer with 3x3 kernel size and 8 filters, followed by a fully connected layer.
  - conv3-16-full-100: model with one convolutional layer with 3x3 kernel size and 16 filters, followed by a fully connected layer.

- `openfhe/inputs/` contains the input and output files:
  - airplain.png/luis.png: input images to be classified.

- `openfhe/notebooks/` contains the Jupyter notebooks used to generate the weights from PT models to binary files can be used in OpenFHE.

- `openfhe/cifar10.cpp/` contains the implementation of HE-based convolutional layers, fully connected layers, and activation functions.
  - HE-based convolutional layers is implemented following "[Encrypted Image Classification with Low Memory Footprint Using Fully Homomorphic Encryption](https://www.worldscientific.com/doi/10.1142/S0129065724500254)"
  - HE-based fully connected layers is implemented following "[GAZELLE: A Low Latency Framework for Secure Neural Network Inference](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-juvekar.pdf)"
  - HE-based activation functions we choose to Square activation function.

## Lattigo
### Quick Start
```bash
cd lattigo

go run setup.go --sk temps/sk.bin --cc temps/cc.bin --input temps/in.bin --key_public temps/pub.bin --key_eval temps/mult.bin

go run main.go --cc temps/cc.bin --input temps/in.bin --output temps/out.bin --key_public temps/pub.bin --key_eval temps/mult.bin

go run verify.go --sk temps/sk.bin --cc temps/cc.bin --input temps/in.bin --output temps/out.bin
```
### Explanation
The code is organized as follows:
- `lattigo/weights/` contains the weights of the model:
  - conv3x8-full-90: model with one convolutional layer with 3x3 kernel size and 8 filters, followed by a fully connected layer.
  - conv3-16-full-100: model with one convolutional layer with 3x3 kernel size and 16 filters, followed by a fully connected layer.
- `lattigo/internal/solution/solution.go` contains the implementation of HE-based convolutional layers, fully connected layers, and activation functions.

## Performance
- OpenFHE: 93% accuracy with 1.27s latency for one image.
- Lattigo: 92% accuracy with 2.15s latency for one image.
