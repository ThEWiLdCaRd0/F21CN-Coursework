import subprocess
import sys

def show_menu():
    print("\n" + "="*50)
    print("  MERKLE-HELLMAN KNAPSACK CRYPTOSYSTEM")
    print("="*50)
    print("1. Generate Keys (Run keygen.py)")
    print("2. Encrypt Message (Run encryption.py)")
    print("3. Decrypt Message (Run decryption.py)")
    print("4. Exit")
    print("="*50)

def run_script(script_name):
    """Run a Python script as a subprocess"""
    try:
        print(f"\n--- Running {script_name} ---\n")
        result = subprocess.run([sys.executable, script_name], check=True)
        print(f"\n--- {script_name} completed ---")
    except subprocess.CalledProcessError:
        print(f"\nError: {script_name} encountered an error.")
    except FileNotFoundError:
        print(f"\nError: {script_name} not found in the current directory.")

def main():
    while True:
        show_menu()
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            run_script('keygen.py')
        elif choice == '2':
            run_script('encryption.py')
        elif choice == '3':
            run_script('decryption.py')
        elif choice == '4':
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please select 1-4.")
        
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
