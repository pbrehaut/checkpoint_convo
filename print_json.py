import json


def load_and_save_formatted_json(input_file_path, output_file_path=None):
    try:
        # Load JSON from input file
        with open(input_file_path, 'r') as file:
            data = json.load(file)
        # Print the formatted JSON
        print(json.dumps(data, indent=4))
        # If output file path is not specified, use input filename + "_formatted.json"
        if output_file_path is None:
            output_file_path = input_file_path.rsplit('.', 1)[0] + "_formatted.json"
        # Save formatted JSON to output file
        with open(output_file_path, 'w') as file:
            json.dump(data, file, indent=4)
        print(f"Formatted JSON saved to '{output_file_path}'")
        return data
    except FileNotFoundError:
        print(f"Error: File '{input_file_path}' not found.")
    except json.JSONDecodeError:
        print(f"Error: File '{input_file_path}' is not valid JSON.")
    except Exception as e:
        print(f"Error: {e}")


# Usage example
if __name__ == "__main__":
    input_file_path = "AUWHCEDGEvFW_Policy_objects.json"  # Replace with your JSON file path
    output_file_path = "data_formatted.json"  # Optional: specify output file path
    # Either specify both input and output paths
    load_and_save_formatted_json(input_file_path, output_file_path)
    # Or just specify input path and use default naming for output
    # load_and_save_formatted_json(input_file_path)