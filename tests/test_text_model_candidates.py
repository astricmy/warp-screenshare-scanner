import unittest
from unittest.mock import patch

from warp_scanner import text_model


class CandidateTests(unittest.TestCase):
    def test_unlisted_calls_with_code_context_propose_local_review(self):
        candidate = text_model.review_candidate(
            "local before = getthreadidentity()\nsetthreadidentity(before) -- CANARIO_DADO_PRIVADO")
        self.assertEqual(candidate, "Consulta e alteração da identidade da thread no mesmo trecho.")

    def test_model_can_abstain_even_with_matching_calls(self):
        code = "local val = gethiddenproperty(part, key); sethiddenproperty(part, key, val)"
        with patch.object(text_model, "review_priority", return_value=text_model.UNKNOWN):
            self.assertIsNone(text_model.review_candidate(code))

    def test_docs_comments_literals_and_mock_methods_do_not_trigger(self):
        examples = (
            "Tutorial: getthreadidentity() e setthreadidentity()",
            "```lua\nlocal x=getthreadidentity(); setthreadidentity(x)\n```",
            "local op=getthreadidentity() -- setthreadidentity(1)",
            "local op=getthreadidentity() --[=[\nsetthreadidentity(1)\n]=]",
            'local op=getthreadidentity(); print("setthreadidentity(1)")',
            'local example=[==[getthreadidentity(); setthreadidentity(1)]==]',
            'local s = obj.getthreadidentity(); obj:setthreadidentity(s)',
            "local function getthreadidentity() end\nlocal x=getthreadidentity(); setthreadidentity(x)",
            "local score = player:GetAttribute('score'); player:SetAttribute('score', score)",
        )
        for sample in examples:
            with self.subTest(sample=sample):
                self.assertIsNone(text_model.review_candidate(sample))
