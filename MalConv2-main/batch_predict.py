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
    parser = argparse.ArgumentParser(description='Batch predict malware probability for files in a folder using MalConvGCT')
    parser.add_argument('--data_dir', type=str, default='data', help='Path to the directory containing files')
    parser.add_argument('--output_file', type=str, default='results.txt', help='Path to the output text file')
    parser.add_argument('--checkpoint', type=str, default='malconvGCT_nocat.checkpoint', help='Path to the model checkpoint')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.data_dir):
        print(f"Data directory not found: {args.data_dir}")
        sys.exit(1)
        
    if not os.path.exists(args.checkpoint):
        print(f"Checkpoint not found: {args.checkpoint}")
        sys.exit(1)

    # Load the model
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

    files = [f for f in os.listdir(args.data_dir) if os.path.isfile(os.path.join(args.data_dir, f))]
    
    print(f"Found {len(files)} files in {args.data_dir}")
    
    with open(args.output_file, 'w') as out_f:
        # Write header
        out_f.write("Filename\tProbability\tResult\n")
        
        for filename in files:
            file_path = os.path.join(args.data_dir, filename)
            print(f"Processing: {filename}")
            
            input_tensor = read_file(file_path)
            
            if input_tensor is None:
                continue
                
            # Add batch dimension (1, length)
            input_tensor = input_tensor.unsqueeze(0)
            
            try:
                with torch.no_grad():
                    output = model(input_tensor)
                    # The output is a tuple (logits, penult, post_conv)
                    logits = output[0]
                    
                    prob = torch.nn.functional.softmax(logits, dim=1)
                    malware_prob = prob[0][1].item()
                
                result_str = "MALWARE" if malware_prob > 0.5 else "BENIGN"
                
                # Write result to file
                line = f"{filename}\t{malware_prob:.4f}\t{result_str}\n"
                out_f.write(line)
                out_f.flush() # Ensure it's written immediately
                
            except Exception as e:
                print(f"Error processing {filename}: {e}")

    print(f"Batch processing complete. Results saved to {args.output_file}")

if __name__ == '__main__':
    main()
