import csv
import matplotlib.pyplot as plt
import numpy as np
import os

def generate_triage_graphs(csv_path="hydroad_triage_metrics.csv"):
    """
    Reads the evaluation metrics from the CSV file and generates
    a professional bar chart comparing model overall accuracy.
    """
    if not os.path.exists(csv_path):
        print(f"[-] Error: Could not find {csv_path}. Please run the evaluator first.")
        return

    models = []
    accuracies = []

    # Read the generated metrics from the evaluator's output
    with open(csv_path, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Clean model names for a cleaner X-axis
            clean_name = row["Model"].split("/")[-1]
            models.append(clean_name)
            
            # Extract accuracy as float
            accuracies.append(float(row["Accuracy (%)"]))

    # ---------------------------------------------------------
    # PLOTTING THE ACCURACY BAR CHART
    # ---------------------------------------------------------
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Create the bars with a professional dark blue/slate color
    bars = ax.bar(models, accuracies, color='#2c3e50', width=0.5, edgecolor='black')

    # Add text, titles, and custom labels
    ax.set_ylabel('Accuracy (%)', fontsize=12, fontweight='bold')
    ax.set_title('Cloud Security Agent: LLM Triage Accuracy', pad=20, fontsize=16, fontweight='bold')
    
    # Set Y-axis to go slightly above 100 so the top labels don't get cut off
    ax.set_ylim(0, 115) 
    
    # Professional touches: horizontal grid lines behind the bars
    ax.yaxis.grid(True, linestyle='--', alpha=0.7)
    ax.set_axisbelow(True)

    # X-axis formatting
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels(models, rotation=15, ha="right", fontsize=11)

    # Attach a text label directly above each bar displaying its numerical percentage
    for bar in bars:
        height = bar.get_height()
        ax.annotate(f'{height:.2f}%',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 5),  # 5 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom',
                    fontweight='bold', fontsize=11)

    # Adjust layout to prevent label cropping
    fig.tight_layout()

    # Save the graph as a high-resolution PNG image
    output_filename = "cloud_security_agent_accuracy.png"
    plt.savefig(output_filename, dpi=300, bbox_inches='tight')
    print(f"[+] Success: Professional accuracy graph generated and saved to {output_filename}")

if __name__ == "__main__":
    generate_triage_graphs()
