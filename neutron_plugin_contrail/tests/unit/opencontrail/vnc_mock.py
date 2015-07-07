#  Copyright (c) 2015 Cloudwatt
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
# @author: Babu Shanmugam - eNovance (Red Hat)

import json
import uuid as UUID

from cfgm_common import exceptions as vnc_exc
import netaddr
from vnc_api import vnc_api


class MockVnc(object):
    resources_collection = dict()
    _kv_dict = dict()

    def __init__(self, *args, **kwargs):
        pass

    def _break_method(self, method):
        rin = method.rindex('_')
        if method.startswith("_cassandra_"):
            return (method[11:rin], "cassandra_" + method[rin+1:])

        return (method[:rin], method[rin+1:])

    class Callables(object):
        def __init__(self, resource_type, resource,
                     resource_collection, server_conn):
            self._resource_type = resource_type.replace('_', '-')
            self._resource = resource
            self._resource_collection = resource_collection
            self._server_conn = server_conn

        def delete_back_refs(self, ref_name, ref_uuid, back_ref_name,
                             back_ref_uuid):
            _ref_name = ref_name
            if (_ref_name not in self._resource_collection or
                    ref_uuid not in self._resource_collection[_ref_name]):
                # TODO(anbu): Implement if needed
                print(" -- Unable to locate %s resource with uuid %s" % (
                    _ref_name, ref_uuid))
            else:
                ref_obj = self._resource_collection[_ref_name][ref_uuid]
                back_ref = getattr(ref_obj, back_ref_name)
                for index, value in enumerate(back_ref):
                    if value['uuid'] == back_ref_uuid:
                        back_ref.pop(index)
                        break

        def update_back_ref(self, ref_name, refs,
                            back_ref_name_, back_ref_obj):
            _ref_name = ref_name[:-5]
            for ref in refs:
                if 'uuid' not in ref:
                    ref['uuid'] = str(UUID.uuid4())
                ref_uuid = ref['uuid']
                if (_ref_name not in self._resource_collection or
                        ref_uuid not in
                        self._resource_collection[_ref_name]):
                    # TODO(anbu): Implement if needed
                    msg = (" -- Unable to locate %s resource with uuid %s"
                           % (_ref_name, ref_uuid))
                    print(msg)
                else:
                    ref_obj = (
                        self._resource_collection[_ref_name][ref_uuid])
                    back_ref = {'uuid': back_ref_obj.uuid,
                                'to': back_ref_obj.get_fq_name()}
                    back_ref_name = ("%s_back_refs"
                                     % back_ref_name_.replace("-", "_"))
                    if hasattr(ref_obj, back_ref_name) and (
                            getattr(ref_obj, back_ref_name)):
                        getattr(ref_obj, back_ref_name).append(back_ref)
                    else:
                        setattr(ref_obj, back_ref_name, [back_ref])

        def _mock_from_dict(self, server_conn, rt):
            @classmethod
            def _wrapper(cls, **kwargs):
                _rt = rt.replace("-", "_")
                return server_conn.resources_collection[_rt][kwargs['uuid']]
            return _wrapper

    class CassandraReadCallables(Callables):
        def __call__(self, **kwargs):
            if 'obj_uuids' in kwargs:
                if set(kwargs['obj_uuids']).issubset(set(self._resource.keys())):
                    return (True, [self._server_conn.obj_to_dict(
                        self._resource[x]) for x in kwargs['obj_uuids']])
            if self._resource_type == 'service-template':
                if 'fq_name' in kwargs and (
                    kwargs['fq_name'] == ['default-domain',
                                          'netns-snat-template']):
                    fq_name_str = ':'.join(kwargs['fq_name'])
                    self._resource[fq_name_str] = vnc_api.ServiceTemplate(
                        fq_name=kwargs['fq_name'])
                    return (True, [self._server_conn.obj_to_dict(
                        self._resource[fq_name_str])])
            # Not found yet
            raise vnc_exc.NoIdError(
                kwargs['obj_uuids'] if 'obj_uuids' in kwargs else '')

    class CassandraListCallables(Callables):
        def __call__(self, back_ref_uuids=None, obj_uuids=None,
                     parent_uuids=None, count=False):
            ret = []
            ret_resource_name = None
            if obj_uuids:
                for res in set(self._resource.values()):
                    if res.uuid in obj_uuids:
                        ret.append(res)
            elif parent_uuids:
                for res in set(self._resource.values()):
                    if res.parent_uuid in parent_uuids:
                        ret.append(res)
            elif back_ref_uuids:
                for res in set(self._resource.values()):
                    back_ref_fields = getattr(res, 'back_ref_fields', [])
                    ref_fields = getattr(res, 'ref_fields', [])
                    back_ref_fields.extend(ref_fields)
                    for field in back_ref_fields:
                        back_ref_field = getattr(res, field, [])
                        for f in back_ref_field:
                            if f['uuid'] in back_ref_uuids:
                                ret.append(res)

                            if field == 'project_refs':
                                if f['uuid'].replace(
                                        '-', '') in back_ref_uuids:
                                    ret.append(res)
            else:
                for res in set(self._resource.values()):
                    ret.append(res)

            if count:
                return (True, len(ret))

            sret = []
            for res in ret:
                sret.append((res.get_fq_name(), res.uuid,))
            return (True, sret)

    class ReadCallables(Callables):
        def __call__(self, **kwargs):
            if 'id' in kwargs:
                if kwargs['id'] in self._resource:
                    return self._resource[kwargs['id']]
            if ('fq_name_str' in kwargs or (
                    'fq_name' in kwargs and kwargs['fq_name'])):
                fq_name_str = (kwargs['fq_name_str']
                               if 'fq_name_str' in kwargs else
                               ':'.join(kwargs['fq_name']))
                if fq_name_str in self._resource:
                    return self._resource[fq_name_str]
            if self._resource_type == 'service-template':
                if 'fq_name' in kwargs and (
                    kwargs['fq_name'] == ['default-domain',
                                          'netns-snat-template']):
                    fq_name_str = ':'.join(kwargs['fq_name'])
                    self._resource[fq_name_str] = vnc_api.ServiceTemplate(
                        fq_name=kwargs['fq_name'])
                    return self._resource[fq_name_str]
            # Not found yet
            raise vnc_exc.NoIdError(
                kwargs['id'] if 'id' in kwargs else fq_name_str)


    class ListCallables(Callables):
        def __call__(self, parent_id=None, parent_fq_name=None,
                     back_ref_id=None, obj_uuids=None, fields=None,
                     detail=False, count=False):
            ret = []
            ret_resource_name = None
            if parent_fq_name:
                for res in set(self._resource.values()):
                    if set(res.get_parent_fq_name()) == set(parent_fq_name):
                        ret.append(res)
            elif obj_uuids:
                for res in set(self._resource.values()):
                    if res.uuid in obj_uuids:
                        ret.append(res)
            elif parent_id:
                for res in set(self._resource.values()):
                    if isinstance(parent_id, list):
                        if res.parent_uuid in parent_id:
                            ret.append(res)
                    elif res.parent_uuid == parent_id:
                        ret.append(res)
            elif back_ref_id:
                for res in set(self._resource.values()):
                    back_ref_fields = getattr(res, 'back_ref_fields', [])
                    ref_fields = getattr(res, 'ref_fields', [])
                    back_ref_fields.extend(ref_fields)
                    for field in back_ref_fields:
                        back_ref_field = getattr(res, field, [])
                        for f in back_ref_field:
                            if f['uuid'] in back_ref_id:
                                ret.append(res)
                            if field == 'project_refs':
                                if f['uuid'].replace('-', '') in back_ref_id:
                                    ret.append(res)
            else:
                for res in set(self._resource.values()):
                    ret.append(res)
            ret_resource_name = self._resource_type + 's'
            if count:
                return {ret_resource_name: {"count": len(ret)}}
            if not detail:
                sret = []
                for res in ret:
                    sret.append(res.serialize_to_json())
                return {ret_resource_name: sret}
            return ret


    class CreateCallables(Callables):
        def _check_if_uuid_in_use(self, uuid_value):
            for res_dict in self._resource_collection.itervalues():
                if uuid_value in res_dict:
                    return True
            return False

        def _mock_add_network_ipam(self, obj):
            actual = obj.add_network_ipam

            def _mock(obj, vnsn_data):
                if 'network_ipam' not in self._resource_collection:
                    self._resource_collection['network_ipam'] = dict()

                fq_name_str = obj.get_fq_name_str()
                if not obj.uuid:
                    obj.uuid = UUID.uuid4()
                uid = obj.uuid

                d = self._resource_collection['network_ipam']
                d[uid] = obj
                d[fq_name_str] = obj

                return actual(obj, vnsn_data)

            obj.add_network_ipam = _mock

        def __call__(self, obj):
            if not obj:
                raise ValueError("Create called with null object")
            uuid = getattr(obj, 'uuid', None)
            obj._server_conn = self._server_conn
            if not uuid:
                uuid = obj.uuid = str(UUID.uuid4())
            else:
                if self._check_if_uuid_in_use(uuid):
                    raise vnc_exc.RefsExistError('')
            if hasattr(obj, 'parent_type'):
                if obj.parent_type == 'project':
                    parent = self._server_conn.project_read(
                        fq_name=obj.fq_name[:-1])
                else:
                    parent_res = self._resource_collection[
                            obj.parent_type.replace("-", "_")]
                    parent = parent_res[":".join(obj.fq_name[:-1])]
                obj.parent_uuid = parent.uuid

            fq_name_str = getattr(obj, 'fq_name_str', None)
            if not fq_name_str:
                fq_name_str = ":".join(obj.get_fq_name())

            self._resource[uuid] = obj

            for field in obj._pending_field_updates:
                if field.endswith("_refs"):
                    for r in getattr(obj, field):
                        setattr(obj, "processed_" + field,
                                list(getattr(obj, field)))
                        self.update_back_ref(field, getattr(obj, field),
                                             self._resource_type, obj)

            self._pending_ref_updates = self._pending_field_updates = set([])

            if fq_name_str and fq_name_str != uuid:
                if fq_name_str in self._resource:
                    fq_name_str += ("-" + uuid)
                    obj.get_fq_name()[-1] += ('-' + uuid)

                self._resource[fq_name_str] = obj

            obj.__class__.from_dict = self._mock_from_dict(self._server_conn, self._resource_type)
            if self._resource_type == 'virtual-machine-interface':
                # generate a dummy mac address
                def random_mac():
                    import random
                    mac = [0x00, 0x00, 0x00]
                    for i in range(3, 6):
                        mac.append(random.randint(0x00, 0x7f))

                    return ":".join(map(lambda x: "%02x" % x, mac))
                if not obj.get_virtual_machine_interface_mac_addresses():
                    obj.set_virtual_machine_interface_mac_addresses(
                            vnc_api.MacAddressesType([random_mac()]))
            elif self._resource_type == "instance-ip" or \
                 self._resource_type == "floating-ip":
                if self._resource_type == 'instance-ip':
                    vn = obj.get_virtual_network_refs()[0]['uuid']
                else:
                    pool_obj = self._resource_collection['floating_ip_pool'][
                        ":".join(obj.get_fq_name()[:-1])]
                    vn = ":".join(pool_obj.get_fq_name()[:-1])
                vn_obj = self._resource_collection['virtual_network'][vn]
                if (self._resource_type == 'instance-ip' and not obj.get_instance_ip_address()) or \
                   (self._resource_type == 'floating-ip' and not obj.get_floating_ip_address()):
                    subnet = None
                    if (self._resource_type == 'instance-ip' and not obj.subnet_uuid):
                        subnet = vn_obj.get_network_ipam_refs(
                            )[0]['attr'].get_ipam_subnets()[0]
                        obj.subnet_uuid = subnet.subnet_uuid
                    else:
                        for ipams in vn_obj.get_network_ipam_refs():
                            for subnet in ipams['attr'].get_ipam_subnets():
                                if self._resource_type == 'floating-ip':
                                    break
                                if subnet.subnet_uuid == obj.subnet_uuid:
                                    break

                    if subnet:
                        subnet_cidr = '%s/%s' % (
                            subnet.subnet.ip_prefix,
                            subnet.subnet.ip_prefix_len)

                        cidr_obj = netaddr.IPNetwork(subnet_cidr)
                        if not hasattr(subnet.subnet, 'ip_prefixed'):
                            setattr(subnet.subnet, "ip_prefixed", 0)
                        if (netaddr.IPAddress(
                                subnet.default_gateway).words[-1] == (
                                    subnet.subnet.ip_prefixed + 1)):
                            subnet.subnet.ip_prefixed += 2
                        else:
                            subnet.subnet.ip_prefixed += 1
                        ip_address = (netaddr.IPAddress(
                            subnet.subnet.ip_prefix) +
                            subnet.subnet.ip_prefixed)
                        if ip_address not in cidr_obj:
                            rc = MockVnc.DeleteCallables(
                                self._resource_type,
                                self._resource,
                                self._resource_collection,
                                self._server_conn)
                            rc(id=uuid)
                            raise vnc_exc.HttpError(status_code=409,
                                                    content='')
                        if self._resource_type == 'instance-ip':
                            obj.set_instance_ip_address(str(ip_address))
                        else:
                            obj.set_floating_ip_address(str(ip_address))
                else:
                    for ipams in vn_obj.get_network_ipam_refs():
                        for subnet in ipams['attr'].get_ipam_subnets():
                            if self._resource_type == 'floating-ip':
                                break
                            if subnet.subnet_uuid == obj.subnet_uuid:
                                break
                    subnet_cidr = '%s/%s' % (
                        subnet.subnet.ip_prefix, subnet.subnet.ip_prefix_len)
                    if (self._resource_type == 'instance-ip' and (
                        netaddr.IPAddress(obj.get_instance_ip_address(
                            )) not in netaddr.IPNetwork(subnet_cidr))) or \
                       (self._resource_type == 'floating-ip' and (
                        netaddr.IPAddress(obj.get_floating_ip_address()) not in
                        netaddr.IPNetwork(subnet_cidr))):
                        rc = MockVnc.DeleteCallables(
                            self._resource_type,
                            self._resource,
                            self._resource_collection,
                            self._server_conn)
                        rc(id=uuid)
                        raise vnc_exc.HttpError(status_code=400, content="")
            elif self._resource_type == 'security-group':
                if not obj.get_id_perms():
                    obj.set_id_perms(
                        vnc_api.IdPermsType(enable=True))
                proj_obj = self._resource_collection['project'][
                    obj.parent_uuid]
                sgs = getattr(proj_obj, 'security_groups', None)
                sg_ref = {'to': obj.get_fq_name(), 'uuid': obj.uuid}
                if not sgs:
                    setattr(proj_obj, 'security_groups', [sg_ref])
                else:
                    sgs.append(sg_ref)

            elif self._resource_type == 'virtual-network':
                self._mock_add_network_ipam(obj)

            return uuid

    class UpdateCallables(Callables):
        def __call__(self, obj):
            if obj.uuid:
                cur_obj = self._resource[obj.uuid]
            else:
                cur_obj = self._resource[':'.join(obj.get_fq_name())]

            if obj._pending_ref_updates:
                for ref in obj._pending_ref_updates:
                    if ref.endswith("_refs"):
                        proc_refs = getattr(cur_obj, "processed_" + ref, [])
                        obtained_refs = getattr(cur_obj, ref)
                        if len(obtained_refs) > len(proc_refs):
                            self.update_back_ref(ref, getattr(obj, ref),
                                                 self._resource_type, cur_obj)
                        elif len(obtained_refs) < len(proc_refs):
                            proc_uuids = [x['uuid'] for x in proc_refs]
                            obtained_uuids = [x['uuid']
                                              for x in obtained_refs]
                            back_ref_name = (
                                self._resource_type.replace("-", "_") +
                                "_back_refs")
                            ref_name = ref[:-5]
                            for i in set(proc_uuids) - set(obtained_uuids):
                                self.delete_back_refs(ref_name, i,
                                                      back_ref_name, obj.uuid)
                        setattr(cur_obj, "processed_" + ref,
                                list(getattr(cur_obj, ref)))

            if obj._pending_field_updates:
                for ref in obj._pending_field_updates:
                    if ref.endswith("_refs"):
                        setattr(obj, "processed_" + ref,
                                list(getattr(cur_obj, ref)))
                        self.update_back_ref(ref, getattr(cur_obj, ref),
                                             self._resource_type, cur_obj)

    class DeleteCallables(Callables):
        _refs_excluded_resources = {}
        _refs_excluded_resources['service-instance'] = (
            ['logical_router_back_refs'])
        _refs_excluded_resources['virtual-machine-interface'] = (
            ['floating_ip_back_refs'])
        _refs_excluded_resources['security-group'] = (
            ['virtual_machine_interface_back_refs'])

        def _backref_excluded(self, resource, back_refs):
            excluded_list = self._refs_excluded_resources.get(
                resource)
            if excluded_list:
                if back_refs in excluded_list:
                    return True
            return False

        def __call__(self, **kwargs):
            obj = None
            if 'fq_name' in kwargs and kwargs['fq_name']:
                fq_name_str = ':'.join(kwargs['fq_name'])
                obj = self._resource[fq_name_str]

            if 'id' in kwargs and kwargs['id'] in self._resource:
                obj = self._resource[kwargs['id']]

            if not obj:
                raise vnc_exc.NoIdError(
                    kwargs['id'] if 'id' in kwargs else None)

            for ref in obj.backref_fields:
                if getattr(obj, "get_" + ref)():
                    if not self._backref_excluded(self._resource_type, ref):
                        print(" -- Cannot delete %s resource as it still "
                              "has %s refs %s"
                              % (self._resource_type, ref,
                                 getattr(obj, "get_" + ref)()))
                        raise vnc_exc.RefsExistError()

            self._resource.pop(obj.uuid)
            self._resource.pop(':'.join(obj.get_fq_name()), None)

            # remove all the back refs
            for ref in obj.ref_fields:
                back_ref_name = (self._resource_type.replace("-", "_") +
                                 "_back_refs")
                ref_name = ref[:-5]
                if not hasattr(obj, ref):
                    continue
                ref_value = getattr(obj, "processed_" + ref, None)
                if not ref_value:
                    ref_value = getattr(obj, ref)
                for r in ref_value:
                    self.delete_back_refs(ref_name, r['uuid'],
                                          back_ref_name,
                                          obj.uuid)

    def __getattr__(self, method):
        print(" -- vnc_method %s" % method)
        (resource, action) = self._break_method(method)
        if action not in ['list', 'read', 'create',
                          'cassandra_list', 'cassandra_read',
                          'update', 'delete']:
            raise ValueError("Unknown action %s received for %s method" %
                             (action, method))

        if action == 'list':
            # for 'list' action resource will be like resourceS
            resource = resource[:-1]

        callables_map = {'list': MockVnc.ListCallables,
                         'cassandra_list': MockVnc.CassandraListCallables,
                         'cassandra_read': MockVnc.CassandraReadCallables,
                         'read': MockVnc.ReadCallables,
                         'create': MockVnc.CreateCallables,
                         'update': MockVnc.UpdateCallables,
                         'delete': MockVnc.DeleteCallables}

        if resource not in self.resources_collection:
            self.resources_collection[resource] = dict()

        return callables_map[action](
            resource, self.resources_collection[resource],
            self.resources_collection, self)

    def _obj_serializer_all(self, obj):
        if hasattr(obj, 'serialize_to_json'):
            return obj.serialize_to_json()
        else:
            d = dict((k, v) for k, v in obj.__dict__.iteritems())
            d.pop('_pending_field_updates', None)
            d.pop('_pending_ref_updates', None)
            d.pop('prop_fields', None)
            d.pop('back_ref_fields', None)
            d.pop('ref_fields', None)
            d.pop('children_fields', None)
            return d

    def obj_to_json(self, obj):
        return json.dumps(obj, default=self._obj_serializer_all)

    def obj_to_dict(self, obj):
        return json.loads(self.obj_to_json(obj))

    def obj_to_id(self, obj):
        if obj.uuid:
            return obj.uuid
        else:
            return "%031d" % 0

    def kv_store(self, key, value):
        self._kv_dict[key] = value

    def kv_retrieve(self, key):
        try:
            return self._kv_dict[key]
        except KeyError:
            raise vnc_exc.NoIdError(key)

    def kv_delete(self, key):
        return self._kv_dict.pop(key, None)

    def fq_name_to_id(self, resource, fq_name):
        res = resource.replace("-", "_")
        fq_name_str = ":".join(fq_name)
        obj = self.resources_collection[res].get(fq_name_str, None)
        return obj.uuid if obj else None

    def project_read(self, **kwargs):
        fq_name_str = None
        uid = None
        if 'id' in kwargs:
            uid = kwargs['id']
            if 'project' not in self.resources_collection or (
                    kwargs['id'] not in self.resources_collection['project']):
                fq_name_str = "default-domain:%s" % kwargs['id']

        if ('fq_name_str' in kwargs or (
                'fq_name' in kwargs and kwargs['fq_name'])):
            fq_name_str = (kwargs['fq_name_str']
                           if 'fq_name_str' in kwargs else
                           ':'.join(kwargs['fq_name']))

        if 'project' not in self.resources_collection or (
                fq_name_str and fq_name_str not in (
                    self.resources_collection['project'])):
            fq_name = fq_name_str.split(":")
            domain_obj = self.domain_read(fq_name_str=fq_name[0])
            proj_obj = vnc_api.Project(parent_obj=domain_obj,
                                       name=fq_name[-1])
            if uid:
                proj_obj.uuid = uid
            self.project_create(proj_obj)
            if not uid:
                uid = proj_obj.uuid
        else:
            if not uid:
                uid = self.resources_collection['project'][fq_name_str].uuid

        _, proj_dict = MockVnc.CassandraReadCallables(
            'project', self.resources_collection['project'],
            self.resources_collection, self)(obj_uuids=[uid])
        return vnc_api.Project.from_dict(**proj_dict[0])
