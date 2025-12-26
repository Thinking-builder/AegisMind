import sys
import os
import argparse
import torch
import numpy as np
from MalConvGCT_nocat import MalConvGCT

def read_file(file_path, max_len=4000000):
    """
    Reads a file and converts it to a tensor, similar to BinaryDataset.__getitem__
    """
    try:
        with open(file_path, 'rb') as f:
            x = f.read(max_len)
            x = np.frombuffer(x, dtype=np.uint8).astype(np.int16) + 1
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None
    
    x = torch.tensor(x)
    return x

def main():
    parser = argparse.ArgumentParser(description='Predict malware probability for an EXE file using MalConvGCT')
    parser.add_argument('file_path', type=str, help='Path to the EXE file')
    parser.add_argument('--checkpoint', type=str, default='malconvGCT_nocat.checkpoint', help='Path to the model checkpoint')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"File not found: {args.file_path}")
        sys.exit(1)
        
    if not os.path.exists(args.checkpoint):
        print(f"Checkpoint not found: {args.checkpoint}")
        sys.exit(1)

    # Load the model
    # Parameters from README.md
    print("Loading model...")
    try:
        model = MalConvGCT(channels=256, window_size=256, stride=64, low_mem=False)
        checkpoint = torch.load(args.checkpoint, map_location=torch.device('cpu'))
        
        # The checkpoint might contain 'model_state_dict' or just the state dict
        if 'model_state_dict' in checkpoint:
            model.load_state_dict(checkpoint['model_state_dict'], strict=False)
        else:
            model.load_state_dict(checkpoint, strict=False)
            
        model.eval()
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)

    # Process the file
    print(f"Processing file: {args.file_path}")
    input_tensor = read_file(args.file_path)
    
    if input_tensor is None:
        sys.exit(1)
        
    # Add batch dimension (1, length)
    input_tensor = input_tensor.unsqueeze(0)
    
    # Run inference
    print("Running inference...")
    with torch.no_grad():
        output = model(input_tensor)
        # The output is a tuple (logits, penult, post_conv)
        logits = output[0]
        
        prob = torch.nn.functional.softmax(logits, dim=1)
        malware_prob = prob[0][1].item()
        
    print(f"Malware Probability: {malware_prob:.4f}")
    if malware_prob > 0.5:
        print("Result: MALWARE")
    else:
        print("Result: BENIGN")

if __name__ == '__main__':
    main()
