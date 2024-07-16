import streamlit as st
import requests
import json
from typing import Dict

# Constants
# API_BASE_URL = "http://0.0.0.0:8000"
API_BASE_URL = st.secrets["API_BASE_URL"]
API_KEY = st.secrets["API_KEY"]

# UI Customization Options
THEMES = {
    "Accessible Light": {
        "bg_color": "#FFFFFF",
        "text_color": "#000000",
        "accent_color": "#1E90FF",  # High contrast accent color
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "Accessible Dark": {
        "bg_color": "#1C1C1C",
        "text_color": "#FFFFFF",
        "accent_color": "#FFD700",  # High contrast accent color
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "Pastel": {
        "bg_color": "#FFF5E6",
        "text_color": "#5D4037",
        "accent_color": "#FF9800",
        "font_size": "16px",  # Slightly larger font size for readability
    },
    "High Contrast": {
        "bg_color": "#000000",
        "text_color": "#FFFFFF",
        "accent_color": "#FF0000",  # Red for strong visual contrast
        "font_size": "18px",  # Larger font size for readability
    },
    "Solarized Light": {
        "bg_color": "#FDF6E3",
        "text_color": "#657B83",
        "accent_color": "#268BD2",
        "font_size": "16px",
    },
    "Solarized Dark": {
        "bg_color": "#002B36",
        "text_color": "#839496",
        "accent_color": "#B58900",
        "font_size": "16px",
    },
}


FONTS = ["Arial", "Roboto", "Helvetica", "Times New Roman", "Courier"]

# Language options
LANGUAGES = {
    "afrikaans": "af",
    "albanian": "sq",
    "amharic": "am",
    "arabic": "ar",
    "armenian": "hy",
    "assamese": "as",
    "aymara": "ay",
    "azerbaijani": "az",
    "bambara": "bm",
    "basque": "eu",
    "belarusian": "be",
    "bengali": "bn",
    "bhojpuri": "bho",
    "bosnian": "bs",
    "bulgarian": "bg",
    "catalan": "ca",
    "cebuano": "ceb",
    "chichewa": "ny",
    "chinese (simplified)": "zh-CN",
    "chinese (traditional)": "zh-TW",
    "corsican": "co",
    "croatian": "hr",
    "czech": "cs",
    "danish": "da",
    "dhivehi": "dv",
    "dogri": "doi",
    "dutch": "nl",
    "english": "en",
    "esperanto": "eo",
    "estonian": "et",
    "ewe": "ee",
    "filipino": "tl",
    "finnish": "fi",
    "french": "fr",
    "frisian": "fy",
    "galician": "gl",
    "georgian": "ka",
    "german": "de",
    "greek": "el",
    "guarani": "gn",
    "gujarati": "gu",
    "haitian creole": "ht",
    "hausa": "ha",
    "hawaiian": "haw",
    "hebrew": "iw",
    "hindi": "hi",
    "hmong": "hmn",
    "hungarian": "hu",
    "icelandic": "is",
    "igbo": "ig",
    "ilocano": "ilo",
    "indonesian": "id",
    "irish": "ga",
    "italian": "it",
    "japanese": "ja",
    "javanese": "jw",
    "kannada": "kn",
    "kazakh": "kk",
    "khmer": "km",
    "kinyarwanda": "rw",
    "konkani": "gom",
    "korean": "ko",
    "krio": "kri",
    "kurdish (kurmanji)": "ku",
    "kurdish (sorani)": "ckb",
    "kyrgyz": "ky",
    "lao": "lo",
    "latin": "la",
    "latvian": "lv",
    "lingala": "ln",
    "lithuanian": "lt",
    "luganda": "lg",
    "luxembourgish": "lb",
    "macedonian": "mk",
    "maithili": "mai",
    "malagasy": "mg",
    "malay": "ms",
    "malayalam": "ml",
    "maltese": "mt",
    "maori": "mi",
    "marathi": "mr",
    "meiteilon (manipuri)": "mni-Mtei",
    "mizo": "lus",
    "mongolian": "mn",
    "myanmar": "my",
    "nepali": "ne",
    "norwegian": "no",
    "odia (oriya)": "or",
    "oromo": "om",
    "pashto": "ps",
    "persian": "fa",
    "polish": "pl",
    "portuguese": "pt",
    "punjabi": "pa",
    "quechua": "qu",
    "romanian": "ro",
    "russian": "ru",
    "samoan": "sm",
    "sanskrit": "sa",
    "scots gaelic": "gd",
    "sepedi": "nso",
    "serbian": "sr",
    "sesotho": "st",
    "shona": "sn",
    "sindhi": "sd",
    "sinhala": "si",
    "slovak": "sk",
    "slovenian": "sl",
    "somali": "so",
    "spanish": "es",
    "sundanese": "su",
    "swahili": "sw",
    "swedish": "sv",
    "tajik": "tg",
    "tamil": "ta",
    "tatar": "tt",
    "telugu": "te",
    "thai": "th",
    "tigrinya": "ti",
    "tsonga": "ts",
    "turkish": "tr",
    "turkmen": "tk",
    "twi": "ak",
    "ukrainian": "uk",
    "urdu": "ur",
    "uyghur": "ug",
    "uzbek": "uz",
    "vietnamese": "vi",
    "welsh": "cy",
    "xhosa": "xh",
    "yiddish": "yi",
    "yoruba": "yo",
    "zulu": "zu",
}


def apply_custom_css(theme, font):
    st.markdown(
        f"""
    <style>
    .stApp {{
        background-color: {theme['bg_color']};
        color: {theme['text_color']};
    }}
    .stButton>button {{
        background-color: {theme['accent_color']};
        color: {theme['bg_color']};
    }}
    body {{
        font-family: {font}, sans-serif;
    }}
    </style>
    """,
        unsafe_allow_html=True,
    )


def send_query(prompt, teacher_name, target_language):
    try:
        response = requests.post(
            f"{API_BASE_URL}/combined_query",
            json={
                "query_text": prompt,
                "teacher_name": teacher_name,
                "target_language": target_language,
            },
            headers={
                "accept": "application/json",
                "Content-Type": "application/json",
                "API-Key": API_KEY,
            },
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"An error occurred: {str(e)}")
        return None


def searchable_dropdown(options: Dict[str, str], key: str) -> str:
    container = st.container()
    selected = container.selectbox(
        "Select or type to search",
        options.keys(),
        key=f"{key}_select",
        format_func=lambda x: x.title(),
    )

    filtered_options = {
        k: v for k, v in options.items() if selected.lower() in k.lower()
    }

    if len(filtered_options) == 1:
        selected = list(filtered_options.keys())[0]
    elif filtered_options:
        selected = container.selectbox(
            "Filtered options",
            filtered_options.keys(),
            key=f"{key}_filtered",
            format_func=lambda x: x.title(),
        )

    return options[selected]


def main():
    st.title("Educational Query Assistant")

    # Sidebar for customization
    st.sidebar.title("Customize Your Experience")
    theme_name = st.sidebar.selectbox("Choose a theme", list(THEMES.keys()))
    font = st.sidebar.selectbox("Choose a font", FONTS)

    # Apply custom CSS
    apply_custom_css(THEMES[theme_name], font)

    # User preferences
    teacher_name = st.selectbox("Select Teacher", ["drvinay", "lewas", "historyoftech"])

    # Searchable language dropdown
    st.subheader("Select Output Language")
    target_language = searchable_dropdown(LANGUAGES, "language")

    # Query input
    prompt = st.text_area("Enter your question:", height=100)

    if st.button("Submit Query"):
        if prompt:
            with st.spinner("Processing your query..."):
                result = send_query(prompt, teacher_name, target_language)

            if result and result.get("status") == "success":
                st.success("Query processed successfully!")

                # Display the results
                st.subheader("Professor's Notes")
                st.write(result["result"]["Professor's Notes"])

                st.subheader("Internet Notes")
                st.write(result["result"]["Internet Notes"])

                st.subheader("Sources")
                st.write("Professor's Sources:")
                for source in result["result"]["Professor's Sources"]:
                    st.write(f"- {source}")

                st.write("Internet Sources:")
                for source in result["result"]["Internet Sources"]:
                    st.write(f"- {source}")

                if result["result"]["Extra Sources"]:
                    st.subheader("Extra Sources")
                    for source in result["result"]["Extra Sources"]:
                        st.write(f"- {source}")
            else:
                st.error("Failed to process query. Please try again.")
        else:
            st.warning("Please enter a query before submitting.")


if __name__ == "__main__":
    main()
