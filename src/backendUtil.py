# def forgot_password_form():
#     st.write("Debug: Entering forgot_password_form()")
#     st.subheader("Reset Password")

#     if "reset_stage" not in st.session_state:
#         st.session_state.reset_stage = "request"
#     if "reset_email_value" not in st.session_state:
#         st.session_state.reset_email_value = ""

#     st.write(f"Debug: reset_stage = {st.session_state.reset_stage}")

#     if st.session_state.reset_stage == "request":
#         st.write("Debug: Entering request stage")
#         with st.form("reset_password_form"):
#             email = st.text_input(
#                 "Email", key="reset_email", value=st.session_state.reset_email_value
#             )
#             submit_button = st.form_submit_button("Request Password Reset")

#         if submit_button:
#             st.write("Debug: Password reset requested")
#             if is_valid_email(email):
#                 forgot_password(email)
#                 st.session_state.reset_stage = "confirm"
#                 st.session_state.reset_email_value = email
#                 st.info(
#                     "If your email is registered, you will receive a confirmation code."
#                 )
#                 st.experimental_rerun()
#             else:
#                 st.error("Please enter a valid email address.")

#     elif st.session_state.reset_stage == "confirm":
#         st.info(
#             f"Please enter the confirmation code sent to {st.session_state.reset_email_value}"
#         )
#         confirmation_code = st.text_input("Confirmation Code (Check your email)")
#         new_password = st.text_input("New Password", type="password")
#         confirm_new_password = st.text_input("Confirm New Password", type="password")

#         if st.button("Reset Password"):
#             if new_password == confirm_new_password:
#                 requirements = check_password_requirements(new_password)
#                 if all(met for _, met in requirements):
#                     if confirm_forgot_password(
#                         st.session_state.reset_email_value,
#                         confirmation_code,
#                         new_password,
#                     ):
#                         st.success(
#                             "Password reset successful. You can now log in with your new password."
#                         )
#                         st.session_state.reset_stage = "request"
#                         st.session_state.reset_email_value = ""
#                         # Optionally, you can redirect to the login page here
#                         # st.switch_page("pages/login.py")
#                 else:
#                     st.error(
#                         "Please meet all password requirements for the new password."
#                     )
#             else:
#                 st.error("New passwords do not match.")

#         if st.button("Resend Confirmation Code"):
#             forgot_password(st.session_state.reset_email_value)
#             st.success("Confirmation code resent. Please check your email.")

#         if st.button("Change Email"):
#             st.session_state.reset_stage = "request"
#             st.session_state.reset_email_value = ""
#             st.experimental_rerun()

#     st.write("Debug: Exiting forgot_password_form()")  # Debug line
