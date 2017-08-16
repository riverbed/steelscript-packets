# Copyright (c) 2014 Riverbed Technology, Inc.
#
# This software is licensed under the terms and conditions of the MIT License
# accompanying the software ("License").  This software is distributed "AS IS"
# as set forth in the License.

import unittest
import gitpy_versioning
from mock import patch, MagicMock, mock_open


def test_pep440_public():
    assert gitpy_versioning.valid_public_ver('1.0.dev456')
    assert gitpy_versioning.valid_public_ver('1.0a1')
    assert gitpy_versioning.valid_public_ver('1.0a2.dev456')
    assert gitpy_versioning.valid_public_ver('1.0a12.dev456')
    assert gitpy_versioning.valid_public_ver('1.0a12')
    assert gitpy_versioning.valid_public_ver('1.0b1.dev456')
    assert gitpy_versioning.valid_public_ver('1.0b2')
    assert gitpy_versioning.valid_public_ver('1.0b2.post345.dev456')
    assert gitpy_versioning.valid_public_ver('1.0b2.post345')
    assert gitpy_versioning.valid_public_ver('1.0c1.dev456')
    assert gitpy_versioning.valid_public_ver('1.0c1')
    assert gitpy_versioning.valid_public_ver('1.0rc1')
    assert gitpy_versioning.valid_public_ver('1.0')
    assert gitpy_versioning.valid_public_ver('1.0.post456.dev34')
    assert gitpy_versioning.valid_public_ver('1.0.post456')
    assert gitpy_versioning.valid_public_ver('1.0.dev1')

    assert not gitpy_versioning.valid_public_ver('1.0dev1')
    assert not gitpy_versioning.valid_public_ver('1.0.dev1.post34')
    assert not gitpy_versioning.valid_public_ver('1.0.dev1a1')
    assert not gitpy_versioning.valid_public_ver('1.0.post45a2')
    assert not gitpy_versioning.valid_public_ver('1.0a')
    assert not gitpy_versioning.valid_public_ver('1.0.1.dev')
    assert not gitpy_versioning.valid_public_ver('2.3.4.post')


def test_pep440_local():
    assert gitpy_versioning.valid_local_ver('abcABCdef')
    assert gitpy_versioning.valid_local_ver('AB-d_e.fG')
    assert not gitpy_versioning.valid_local_ver('AB-d_e@.fG')
    assert not gitpy_versioning.valid_local_ver('AB-d_e^.fG')


class GetVersionTestCase(unittest.TestCase):

    def verify_call_sequence(self, patched_func, args):
        """Verify the arguments of each call of patched function

        :param patched_func: patched function to test
        :param args: List of list of arguments for each call
        """
        calls = patched_func.mock_calls
        self.assertEquals(len(calls), len(args))
        for ind in range(len(calls)):
            self.assertEquals(calls[ind].__getnewargs__()[0][1][0], args[ind])

    def test_commit_tagged(self):
        """Test get_version return expected tag when the latest commit is tagged.

        """
        # git ls-files test_gitpy_versioning.py --error-unmatch
        e1 = 'test_gitpy_versioning.py'
        # git branch
        e2 = '  master\n  myreschema\n  new@branch\n  newreschema\n* wreschema'
        # git describe --abbrev=0
        e3 = '0.4.9'
        # git  rev-list 0.4.9
        e4 = ('d3e6528c64441c5a001cecf7e77ed902d8ea7162\n'
              '61bbb9ad956e6f26cdeb2a01131388e84b6a1563\n'
              '77cc046001766d60ffb45008973b3a04361f836a\n'
              '1e309d519cde0bec81ff311c81fa8f0757763b7f\n')
        # git log -n 1 --pretty=format :'%H'
        e5 = "'d3e6528c64441c5a001cecf7e77ed902d8ea7162'"

        args_list = [['ls-files', 'test_gitpy_versioning.py',
                      '--error-unmatch'],
                     ['branch'],
                     ['describe', '--abbrev=0'],
                     ['rev-list', '0.4.9'],
                     ['log', '-n', '1', "--pretty=format:'%H'"]]

        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version(), '0.4.9')

            self.verify_call_sequence(patch_git, args_list)

        # change the tag to be package_name prefixed
        e3 = 'reschema-0.4.9'
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version('reschema'), e3)

            args_list[3][1] = e3
            self.verify_call_sequence(patch_git, args_list)

    def test_parent_branch(self):
        """ Test get_version when recent tag is on a parent branch

        need to mock a git function to return a sequence of results
        """
        # git ls-files test_gitpy_versioning.py --error-unmatch
        e1 = 'test_gitpy_versioning.py'
        # git branch
        e2 = '  child\n* grand-child\n  master'
        # git describe --abbrev=0
        e3 = '1.0'
        # git rev-list 1.0
        e4 = ('aeb6d4612b6da9310ca2859ab53c99edf97fc08c\n'
              'eae4fe83dc592de6e20eca726126ee15b6b21f9b')
        # git log -n 1 --pretty=format:'%H'
        e5 = "'7ce9dfa80816ea61e112b9911f30d812e9567cf5'"
        # git for-each-ref --sort=taggerdate
        #    --format  '%(refname) %(taggerdate)' refs/tags
        e6 = "'refs/tags/1.0 Fri Sep 26 09:59:53 2014 -0400'"
        # git rev-list 1.0
        e7 = e4
        # git branch --contains aeb6d4612b6da9310ca2859ab53c99edf97fc08c
        e8 = '  child\n* grand-child'
        # git show-branch
        e9 = ('! [child] commit-on-child\n'
              ' * [grand-child] commit on grand child\n'
              '  ! [master] commit-on-master\n'
              '---\n'
              ' *  [grand-child] commit on grand child\n'
              '+*  [child] commit-on-child\n'
              '+*+ [master] commit-on-master')
        # git for-each-ref --sort=taggerdate
        #    --format  '%(refname) %(taggerdate)' refs/tags
        e10 = e6
        # git rev-list --count HEAD
        e11 = '4'
        # git rev-list --count 1.0
        e12 = '2'

        args_list = [['ls-files', 'test_gitpy_versioning.py',
                      '--error-unmatch'],
                     ['branch'],
                     ['describe', '--abbrev=0'],
                     ['rev-list', '1.0'],
                     ['log', '-n', '1', "--pretty=format:'%H'"],
                     ['for-each-ref', '--sort=taggerdate', '--format',
                      "'%(refname) %(taggerdate)'", 'refs/tags'],
                     ['rev-list', '1.0'],
                     ['branch', '--contains',
                      'aeb6d4612b6da9310ca2859ab53c99edf97fc08c'],
                     ['show-branch'],
                     ['for-each-ref', '--sort=taggerdate', '--format',
                      "'%(refname) %(taggerdate)'", 'refs/tags'],
                     ['rev-list', '--count', 'HEAD'],
                     ['rev-list', '--count', '1.0']]

        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11, e12])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version(),
                                  '1.0+git.grand-child.2.7ce9dfa')
            self.verify_call_sequence(patch_git, args_list)

        # test with package name prefixing
        e3 = 'version-1.0'
        e6 = "'refs/tags/version-1.0 Fri Sep 26 09:59:53 2014 -0400'"
        e10 = e6
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11, e12])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version('version'),
                                  'version-1.0+git.grand-child.2.7ce9dfa')
            args_list[3][1] = e3
            args_list[6][1] = e3
            args_list[11][2] = e3
            self.verify_call_sequence(patch_git, args_list)

    def test_non_dev_and_dev(self):
        """ Test get_version function when

        1. First test case
        the latest commit is not tagged
        And the recent applicable tag is not on a parent tag
        And the recent applicable tag is non-development version

        2. Second test case
        the latest commit is not tagged
        And the recent applicable tag is not on a parent tag
        And the recent applicable tag is development version
        """

        # git ls-files test_gitpy_versioning.py --error-unmatch
        e1 = 'test_gitpy_versioning.py'
        # git branch
        e2 = '  child\n* grand-child\n  master'
        # git describe --abbrev=0
        e3 = '1.1'
        # git rev-list 1.1
        e4 = ('7ce9dfa80816ea61e112b9911f30d812e9567cf5\n'
              'b6bccdef2df3c0e0293c4ebfa372a82fc328b654\n'
              'aeb6d4612b6da9310ca2859ab53c99edf97fc08c\n'
              'eae4fe83dc592de6e20eca726126ee15b6b21f9b')
        # git log -n 1 --pretty=format:'%H'
        e5 = "'ea1d6aae6b2f89721fc200d752119ffb1bbdc861'"
        # git for-each-ref --sort=taggerdate
        #    --format  '%(refname) %(taggerdate)' refs/tags
        e6 = ("'refs/tags/1.0 Fri Sep 26 09:59:53 2014 -0400'\n"
              "'refs/tags/1.1 Fri Sep 26 11:22:12 2014 -0400'")
        # git rev-list 1.1
        e7 = e4
        # git branch --contains 7ce9dfa80816ea61e112b9911f30d812e9567cf5
        e8 = '* grand-child'
        # git show-branch
        e9 = ('! [child] commit-on-child\n'
              ' * [grand-child] another commit on grandchild\n'
              '  ! [master] commit-on-master\n'
              '---\n'
              ' *  [grand-child] another commit on grandchild\n'
              ' *  [grand-child^] commit on grand child\n'
              '+*  [child] commit-on-child\n'
              '+*+ [master] commit-on-master')
        # git rev-list --count HEAD
        e10 = '5'
        # git rev-list --count 1.1
        e11 = '4'

        args_list = [['ls-files', 'test_gitpy_versioning.py',
                      '--error-unmatch'],
                     ['branch'],
                     ['describe', '--abbrev=0'],
                     ['rev-list', '1.1'],
                     ['log', '-n', '1', "--pretty=format:'%H'"],
                     ['for-each-ref', '--sort=taggerdate', '--format',
                      "'%(refname) %(taggerdate)'", 'refs/tags'],
                     ['rev-list', '1.1'],
                     ['branch', '--contains',
                      '7ce9dfa80816ea61e112b9911f30d812e9567cf5'],
                     ['show-branch'],
                     ['rev-list', '--count', 'HEAD'],
                     ['rev-list', '--count', '1.1']]

        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version(), '1.2.dev1')
            self.verify_call_sequence(patch_git, args_list)

        # test git rev-list --count fallback
        # Instead of returning '5' and '4', return text with that many
        # lines in it.  The contents of the lines are ignored.
        # The last call is replaced by retries without --count.
        fallback_args_list = args_list[:-1]
        fallback_args_list.extend((['rev-list', 'HEAD'],
                                   ['rev-list', '1.1']))
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9,
                                          EnvironmentError,
                                          '1\n2\n3\n4\n5',
                                          '1\n2\n3\n4'])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version(), '1.2.dev1')
            self.verify_call_sequence(patch_git, fallback_args_list)

        # test with package name prefixing
        e3 = 'version-1.1'
        e6 = ("'refs/tags/version-1.0 Fri Sep 26 09:59:53 2014 -0400'\n"
              "'refs/tags/version-1.1 Fri Sep 26 11:22:12 2014 -0400'")
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version('version'),
                                  'version-1.2.dev1')

            args_list[3][1] = e3
            args_list[6][1] = e3
            args_list[10][2] = e3
            self.verify_call_sequence(patch_git, args_list)

        # Test case when the recent applicable tag is development release
        e3 = '1.1.dev1'
        e6 = ("'refs/tags/1.0 Fri Sep 26 09:59:53 2014 -0400'\n"
              "'refs/tags/1.1.dev1 Fri Sep 26 11:22:12 2014 -0400'")
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version(), '1.1.dev2')

            args_list[3][1] = e3
            args_list[6][1] = e3
            args_list[10][2] = e3
            self.verify_call_sequence(patch_git, args_list)

        # Test case when pkg_name prefixing
        e3 = 'version-1.1.dev1'
        e6 = ("'refs/tags/version-1.0 Fri Sep 26 09:59:53 2014 -0400'\n"
              "'refs/tags/version-1.1.dev1 Fri Sep 26 11:22:12 2014 -0400'")
        with patch('gitpy_versioning.git',
                   MagicMock(side_effect=[e1, e2, e3, e4, e5,
                                          e6, e7, e8, e9, e10,
                                          e11])) as patch_git:
            with patch('gitpy_versioning.open', mock_open(), create=True):
                self.assertEquals(gitpy_versioning.get_version('version'),
                                  'version-1.1.dev2')

            args_list[3][1] = e3
            args_list[6][1] = e3
            args_list[10][2] = e3
            self.verify_call_sequence(patch_git, args_list)


if __name__ == '__main__':
    test_pep440_public()
    test_pep440_local()
    unittest.main()
